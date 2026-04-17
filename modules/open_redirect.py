import sys
import threading
import concurrent.futures
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.logger_config import setup_logger
import pandas as pd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Canonical domain we inject — we check if the app redirects to it
EVIL_DOMAIN = "evil.ntusf.test"

# URL parameters that commonly hold redirect targets
REDIRECT_PARAMS = {
    "redirect", "redirect_to", "redirect_url", "redirecturl",
    "next", "return", "return_to", "returnto", "return_url", "returnurl",
    "url", "goto", "target", "rurl", "dest", "destination",
    "redir", "redirect_uri", "continue", "forward", "go", "back",
    "location", "link", "to", "from", "out", "view", "ref",
}

# Payloads ordered from basic to bypass-oriented
PAYLOADS = [
    f"//{ EVIL_DOMAIN}",
    f"https://{EVIL_DOMAIN}",
    f"http://{EVIL_DOMAIN}",
    f"/\\{EVIL_DOMAIN}",
    f"/%2F/{EVIL_DOMAIN}",
    f"/%09/{EVIL_DOMAIN}",
    f"https:/{EVIL_DOMAIN}",
    f"//{EVIL_DOMAIN}/%2F..",
    f"//{ EVIL_DOMAIN}@trusted.com",
    f"https://{EVIL_DOMAIN}#trusted.com",
]


class OpenRedirectScanner:
    def __init__(
        self,
        base_url="",
        proxies=None,
        cookies=None,
        dataframe=None,
        threads=32,
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

    def _request(self, url, method="GET", data=None):
        try:
            kwargs = dict(
                proxies=self.proxies,
                cookies=self.cookies,
                verify=False,
                allow_redirects=False,
                timeout=self.timeout,
            )
            if method == "GET":
                return requests.get(url, **kwargs)
            return requests.post(url, data=data, **kwargs)
        except Exception:
            return None

    def _is_redirected_to_evil(self, response):
        """Return True if Location header points to our evil domain."""
        if response is None:
            return False
        location = response.headers.get("Location", "")
        return EVIL_DOMAIN in location

    def scan_url(self, url, method):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base = urlunparse(parsed._replace(query=""))

        # Collect parameters that look like redirect targets
        suspicious = {k for k in params if k.lower() in REDIRECT_PARAMS}

        for param in suspicious:
            original = params[param]
            for payload in PAYLOADS:
                test_params = dict(params)
                test_params[param] = [payload]
                test_url = f"{base}?{urlencode(test_params, doseq=True)}"
                resp = self._request(test_url, method)
                if self._is_redirected_to_evil(resp):
                    self.logger.info(
                        f"[Open Redirect] {url} — param '{param}' "
                        f"redirects to {resp.headers.get('Location')} "
                        f"with payload: {payload}\n"
                    )
                    with self._lock:
                        self.vulnerable_endpoints.add(url)
                        self.findings[url] = {
                            "param": param,
                            "payload": payload,
                            "location": resp.headers.get("Location", ""),
                            "confidence": 0.95,
                        }
                    return  # one confirmed finding per URL is enough
            params[param] = original

    def gather_results(self):
        self.dataframe["Open_Redirect"] = 0
        if not self.vulnerable_endpoints:
            self.logger.info("No Open Redirect vulnerabilities found\n")
        else:
            for url in self.vulnerable_endpoints:
                self.dataframe.loc[self.dataframe["URL"] == url, "Open_Redirect"] = 1

        path = (
            f"{sys.path[0]}/results/{self.base_url}/DF/"
            f"{self.base_url}_open_redirect.csv"
        )
        self.logger.info(f"Saving Open Redirect results to: {path}")
        self.dataframe.to_csv(path, index=False)

    def run(self, row):
        try:
            self.scan_url(row["URL"], row["Method"])
        except Exception as e:
            self.logger.error(f"Error scanning {row['URL']}: {e}")

    def start_scanning(self):
        self.logger.info("Launching Open Redirect scanner\n")
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

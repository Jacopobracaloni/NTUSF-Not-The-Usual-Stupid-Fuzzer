import sys
import threading
import concurrent.futures
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.logger_config import setup_logger
import pandas as pd
import json
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# (template_expression, expected_evaluated_result, engine_hint)
# The canary technique wraps each expression so we can tell the difference between
# "the response reflects {{7*7}} literally" and "the engine evaluated it to 49".
# Payload sent:  {canary}{expr}{canary}
# True positive: {canary}{result}{canary} appears in response
# False positive: {canary}{expr}{canary} appears unchanged — just reflected
SSTI_PROBES = [
    ("{{7*7}}",         "49",      "Jinja2 / Twig"),
    ("${7*7}",          "49",      "Freemarker / Velocity / EL"),
    ("<%= 7*7 %>",      "49",      "ERB / JSP"),
    ("{{7*'7'}}",       "7777777", "Twig"),
    ("#{7*7}",          "49",      "Ruby / Pebble"),
    ("${{7*7}}",        "49",      "JSTL"),
    ("*{7*7}",          "49",      "Spring SpEL"),
    ("%{7*7}",          "49",      "Struts / OGNL"),
    ("{7*7}",           "49",      "Smarty"),
    ("{{=7*7}}",        "49",      "Mako"),
    ("@(7*7)",          "49",      "Razor"),
]


class SSTIscanner:
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

    def scan_url(self, url, method, get_params, post_params):
        parsed = urlparse(url)
        base = urlunparse(parsed._replace(query=""))

        # Build parameter dicts
        url_params = {}
        if get_params and get_params != "{}":
            try:
                url_params = json.loads(get_params)
            except Exception:
                url_params = parse_qs(parsed.query, keep_blank_values=True)

        body_params = {}
        if method == "POST" and post_params and post_params != "{}":
            try:
                body_params = json.loads(post_params)
            except Exception:
                pass

        def _probe(params, req_method, build_url=True):
            # One canary per scan_url call — unique enough to avoid collisions
            canary = f"ssti{random.randint(100000, 999999)}"

            for param_key in list(params.keys()):
                original = params[param_key]

                for expr, expected_result, engine in SSTI_PROBES:
                    # Build the canary-wrapped payload:
                    #   sent:          {canary}{expr}{canary}
                    #   if evaluated:  {canary}{result}{canary}  ← true positive
                    #   if reflected:  {canary}{expr}{canary}    ← false positive
                    payload = f"{canary}{expr}{canary}"
                    expected_evaluated = f"{canary}{expected_result}{canary}"

                    test_params = dict(params)
                    test_params[param_key] = payload

                    if build_url:
                        test_url = f"{base}?{urlencode(test_params, doseq=True)}"
                        resp = self._request(test_url, req_method)
                    else:
                        resp = self._request(url, req_method, test_params)

                    if resp is None:
                        continue

                    body = resp.text

                    if expected_evaluated in body:
                        # Canary + result found → the engine executed the expression
                        self.logger.info(
                            f"[SSTI] {url} — param '{param_key}' evaluated "
                            f"'{expr}' → '{expected_result}' (engine: {engine})\n"
                        )
                        with self._lock:
                            self.vulnerable_endpoints.add(url)
                            self.findings[url] = {
                                "param": param_key,
                                "payload": payload,
                                "evidence": (
                                    f"Expression '{expr}' evaluated to '{expected_result}' "
                                    f"(confirmed via canary '{canary}')"
                                ),
                                "engine": engine,
                                "confidence": 0.97,
                            }
                        return  # confirmed — no need to try more probes

                    elif payload in body:
                        # Payload reflected verbatim → not evaluated, skip
                        self.logger.debug(
                            f"[SSTI] {url} param '{param_key}': "
                            f"payload reflected as-is, not evaluated\n"
                        )

                params[param_key] = original

        if url_params:
            _probe(url_params, "GET", build_url=True)
        if body_params and url not in self.vulnerable_endpoints:
            _probe(body_params, "POST", build_url=False)

    def gather_results(self):
        self.dataframe["SSTI"] = 0
        if not self.vulnerable_endpoints:
            self.logger.info("No SSTI vulnerabilities found\n")
        else:
            for url in self.vulnerable_endpoints:
                self.dataframe.loc[self.dataframe["URL"] == url, "SSTI"] = 1

        path = (
            f"{sys.path[0]}/results/{self.base_url}/DF/"
            f"{self.base_url}_ssti.csv"
        )
        self.logger.info(f"Saving SSTI results to: {path}")
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
        self.logger.info("Launching SSTI scanner\n")
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

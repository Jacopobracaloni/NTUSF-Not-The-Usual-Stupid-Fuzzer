from concurrent.futures import ThreadPoolExecutor
from modules.xss.scanner import scan
from modules.logger_config import setup_logger
import sys
import json
import pandas as pd
import logging


class XSSscanner:
    def __init__(
        self,
        base_url,
        proxies=None,
        cookies=None,
        dataframe=None,
        delay=5,
        timeout=120,
        threads=32,
    ):
        self.base_url = base_url
        self.proxies = proxies
        self.cookies = cookies
        self.dataframe = dataframe
        self.timeout = timeout
        self.threads = threads
        self.scan = scan
        self.delay = delay
        self.vulnerable_endpoints = set()
        self.logger = setup_logger(__name__)
        self.logger.propagate = False

    def run(self, row):
        try:
            target = row["URL"]
            method = row["Method"]
            getParams = row["GET Params"]
            postParams = row["POST Params"]
            GET = None
            params = {}

            if method == "GET" and getParams != {}:
                GET = True
                params = json.loads(getParams)
            elif method == "POST" and getParams != {}:
                GET = True
                params = json.loads(getParams)
            elif method == "POST" and postParams != {}:
                GET = False
                params = json.loads(postParams)
            else:
                return

            endpoint = self.scan(
                target,
                GET,
                params,
                self.delay,
                self.timeout,
                proxies=self.proxies,
                cookies=self.cookies,
            )
            if endpoint:
                self.vulnerable_endpoints.add(endpoint)
            else:
                return
        except Exception as e:
            self.logger.error(f"Error in threads: {e}")
            return

    def start_scanning(self):
        try:
            if self.dataframe != None:
                df = pd.read_csv(self.dataframe)
            else:
                return
            self.logger.info("Launching the Cross-Site Scripting exploit module\n")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.run, [row for _, row in df.iterrows()])
            df["XSS"] = 0

            if not self.vulnerable_endpoints:
                self.logger.info("The endpoint is not vulnerable to XSS\n")
            else:
                for endpoint in self.vulnerable_endpoints:
                    df.loc[df["URL"] == endpoint, "XSS"] = 1

                path = (
                    f"{sys.path[0]}"
                    + "/results/"
                    + self.base_url
                    + "/DF/"
                    + f"{self.base_url}_xss.csv"
                )
                self.logger.info(f"Saving results of XSS scan to: {path}")
                df.to_csv(path, index=False)
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt detected. Shutting down the program\n")
            sys.exit(0)
        except Exception as e:
            self.logger.error(
                f"Error in execution the ThreadPool: {e}. Shutting down\n"
            )
            sys.exit(0)

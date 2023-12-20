import json
import argparse
from modules.logger_config import setup_logger
from crawler.crawler.settings import *
from crawler.crawler.spiders.website_spider import Crawler
from modules.waf import wafDetector
import scrapy
from scrapy.crawler import CrawlerProcess
from modules.infographics import VulnerabilityAnalysis
from modules.xss.xss import XSSscanner
import pandas as pd
from modules.sql import SQLscanner
from modules.csrf import CSRFscanner
from modules.path_traversal import Traversalscanner
from urllib.parse import urlparse, unquote
import os
import sys
import time
import logging
from ML.ml import URLClassifier
from requests import HTTPError
import requests as r

logger = setup_logger(__name__)
logger.propagate = False
logging.getLogger("scrapy_user_agents.user_agent_picker").setLevel(logging.ERROR)
logging.getLogger("scrapy.core.downloader.tls").setLevel(logging.ERROR)
logging.getLogger("scrapy.downloadermiddlewares.retry").setLevel(logging.ERROR)
logging.getLogger("scrapy.core.engine").setLevel(logging.ERROR)
logging.getLogger("scrapy.extensions").setLevel(logging.ERROR)


def main_crawler(args):
    # Set up Scrapy settings based on the scan type and provided arguments
    try:
        settings = {
            "BOT_NAME": BOT_NAME,
            "SPIDER_MODULES": SPIDER_MODULES,
            "NEWSPIDER_MODULE": NEWSPIDER_MODULE,
            "EXTENSIONS": EXTENSIONS,
            "ROBOTSTXT_OBEY": ROBOTSTXT_OBEY,
            "CONCURRENT_REQUESTS": CONCURRENT_REQUESTS,
            "COOKIES_ENABLED": True,
            "DOWNLOADER_MIDDLEWARES": DOWNLOADER_MIDDLEWARES,
            "DOWNLOAD_FAIL_ON_DATALOSS": DOWNLOAD_FAIL_ON_DATALOSS,
            "ITEM_PIPELINES": ITEM_PIPELINES,
            "LOG_LEVEL": LOG_LEVEL,
            "AUTOTHROTTLE_ENABLED": AUTOTHROTTLE_ENABLED,
            "AUTOTHROTTLE_MAX_DELAY": AUTOTHROTTLE_MAX_DELAY,
            "HTTPCACHE_ENABLED": HTTPCACHE_ENABLED,
            "HTTPCACHE_EXPIRATION_SECS": HTTPCACHE_EXPIRATION_SECS,
            "HTTPCACHE_STORAGE": HTTPCACHE_STORAGE,
            "HTTPCACHE_IGNORE_MISSING": HTTPCACHE_IGNORE_MISSING,
            "HTTPCACHE_DEBUG": HTTPCACHE_DEBUG,
            "HTTPCACHE_IGNORE_HTTP_CODES": HTTPCACHE_IGNORE_HTTP_CODES,
            "REQUEST_FINGERPRINTER_IMPLEMENTATION": REQUEST_FINGERPRINTER_IMPLEMENTATION,
            "TWISTED_REACTOR": TWISTED_REACTOR,
            "FEED_EXPORT_ENCODING": FEED_EXPORT_ENCODING,
        }

        if args.type == "lax":
            settings["DEPTH_LIMIT"] = 100
        if args.type == "strict":
            settings["DEPTH_LIMIT"] = 300
        if args.type == "brutal":
            settings["DEPTH_LIMIT"] = 500

        # Instantiate the CrawlerProcess with the appropriate settings
        logger.info(
            f"Starting crawl of {args.url} with depth limit set to: {settings['DEPTH_LIMIT']}. This might take some time\n\n"
        )
        time.sleep(2)
        start_time = time.time()  # Store the start time

        process = CrawlerProcess(settings)
        crawler = process.create_crawler(Crawler)
        process.crawl(
            crawler,
            start_urls=[args.url],
            proxies=args.proxies,
            login_url=args.login_url,
            username=args.username,
            password=args.password,
            username_field=args.username_field,
            password_field=args.password_field,
            additional_login_params=args.additional_login_params,
            exclude_paths=args.exclude_paths,
            csrf_token_name=args.csrf_token_name,
        )
        process.start()  # This will block until the crawl is finished
        # Once the crawling process has completed
        if crawler.spider.has_error:
            logger.error("An error occurred during the crawl. Exiting.")
            sys.exit(1)
        stats = crawler.stats.get_stats()
        endpoints_crawled = stats.get("response_received_count", 0)
        logger.info(f"{endpoints_crawled} endpoints crawled.")

        # Logging once completed
        path = (
            sys.path[0]
            + "/results/"
            + base_url
            + "/DF/"
            + f"{base_url}_crawled_endpoints.csv"
        )
        elapsed_time = time.time() - start_time
        logger.info(f"Crawl completed in {elapsed_time:.2f} seconds\n")
        logger.info(f"Results are saved in: {path}\n")

    except Exception as e:
        logger.error(f"Error: {e}. Shutting down the program...\n")
        sys.exit(0)
    except KeyboardInterrupt:
        logger.info("Exiting")
        sys.exit(0)


def testing_connection(url, proxy):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0"
        }
        response = r.get(
            url=url, headers=headers, verify=False, proxies=proxy, allow_redirects=True
        )
        if response.status_code != 200 and response.status_code != 302:
            logger.error("Error in establishing connection. Shutting down\n")
            return False
        elif response.status_code == 302:
            if "login" in unquote(response.headers["Location"].lower()):
                logger.error(
                    "Session may be expired. Try chainging the cookies. Shutting down\n"
                )
                return False
        else:
            logger.info("Connection returns 200 OK\n")
            return True
    except HTTPError:
        logger.error("Error in establishing a HTTP connection with the target\n")
        return False
    except Exception as e:
        logger.error(f"Error during connection: {e}. Shutting down\n")
        return False


def module_setup(module_class_name, base_url, proxies, cookies, dataframe, args):
    module_class = globals().get(module_class_name)
    if not module_class:
        logger.error(f"No class found with name {module_class_name}")
        return
    if args.type == "lax":
        threads = 10
        timeout = 20
    if args.type == "strict":
        threads = 20
        timeout = 10
    if args.type == "brutal":
        threads = 32
        timeout = 5

    start = time.time()
    try:
        module = module_class(base_url, proxies, cookies, dataframe, threads, timeout)
        module.start_scanning()
        end = start - time.time()
        logger.info(f"Module {module_class_name} took {end:.2f} seconds to run\n")
    except KeyboardInterrupt as e:
        logger.info("Keyboard interrupt detected. Shutting down")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error running module: {module_class} {e}")
        raise


def load_cookies():
    file_path = os.path.join(sys.path[0], "cookies.json")

    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            try:
                cookies = json.load(f)
                return cookies
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON: {str(e)}")
                return None
    else:
        return None


def main_classifier(args, base_url):
    if args.type == "lax":
        threshold = 0.3
        n_estimators = 1000
    if args.type == "strict":
        threshold = 0.15
        n_estimators = 800
    if args.type == "brutal":
        threshold = 0.00
        n_estimators = 5000

    try:
        logger.info("Firing up the XGBoost ensemble")
        logger.info(
            f"""The chosen settings are:\n- Threshold: {threshold}\n- N° estimators: {n_estimators}\n"""
        )
        start_time = time.time()
        classifier = URLClassifier(
            base_url=base_url, threshold=threshold, n_estimators=n_estimators
        )
        classifier.run()
        elapsed_time = time.time() - start_time
        logger.info(f"The ensemble took {elapsed_time:.2f} seconds to complete\n")
    except Exception as e:
        logger.error(f"Error: {e}. Shutting down the model\n")
        sys.exit(0)
    except KeyboardInterrupt:
        logger.info("Exiting")
        sys.exit(0)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Website Scanner")
        parser.add_argument("--url", type=str, help="Target URL to scan", required=True)

        parser.add_argument(
            "--cookies",
            type=str,
            default=None,
            help="Path to the cookies.json file. If not specified, no cookies will be used",
            required=False,
        )
        parser.add_argument(
            "--proxies",
            type=str,
            default=None,
            help="Proxy to use for requests. E.g., http://127.0.0.1:8080. If not specified, no proxy will be used",
            required=False,
        )

        parser.add_argument(
            "--modules",
            type=str,
            # default=["XSSscanner", "SQLscanner", "CSRFscanner", "Traversalscanner"],
            default=["Traversalscanner"],
            help="Attacking modules in /modules folder. E.g. --modules XSSscanner, SQLscanner, ...",
            required=False,
        )

        parser.add_argument(
            "--type",
            type=str,
            choices=["lax", "strict", "brutal"],
            default="lax",
            required=False,
            help="The type of the scan",
        )
        parser.add_argument(
            "--username",
            type=str,
            default=None,
            required=False,
            help="The login username.",
        )

        parser.add_argument(
            "--password",
            type=str,
            default=None,
            required=False,
            help="The login password.",
        )

        parser.add_argument(
            "--login_url",
            type=str,
            default=None,
            required=False,
            help="The url of the login form.",
        )

        parser.add_argument(
            "--username_field",
            type=str,
            default="username",
            help="The name attribute of the username field in the login form.",
            required=False,
        )
        parser.add_argument(
            "--password_field",
            type=str,
            default="password",
            help="The name attribute of the password field in the login form.",
            required=False,
        )
        parser.add_argument(
            "--additional_login_params",
            type=json.loads,
            default={},
            help="Additional parameters required for login in JSON format.",
            required=False,
        )

        parser.add_argument(
            "--csrf_token_name",
            type=str,
            default="csrf-token",
            help="Name of the CSRF token field in the login form",
        )
        parser.add_argument(
            "--exclude-paths",
            type=str,
            nargs="*",
            default=["logout"],
            help="List of URL paths to exclude",
        )
        args = parser.parse_args()
        # Load session cookies
        if args.proxies != None:
            proxies = {"http": args.proxies, "https": args.proxies}
        else:
            proxies = None
        if testing_connection(args.url, proxies) == True:
            base_url = urlparse(args.url).netloc
            directory_path = "results/" + base_url

            if not os.path.exists(directory_path):
                os.mkdir(directory_path)
            waf, server = wafDetector(args.url)
            if waf:
                logger.warning(
                    f"Web Application Firewall detected: {waf}. The scanner may get blocked or the payloads may not work\n"
                )
            else:
                logger.info("Web Application Firewall status Offline\n")
            if server:
                logger.info(f"Server type found: {server}\n")
            else:
                logger.info("No Server Header found in the HTTP response\n")

            DF = f"{sys.path[0]}" + "/results/" + base_url + "/DF/"
            IMG = f"{sys.path[0]}" + "/results/" + base_url + "/IMG/"
            filtered_data = DF + f"{base_url}_filtered_data.csv"
            # main_crawler(args)
            main_classifier(args, base_url)
            results = pd.read_csv(filtered_data)
            logger.info("Launching the attacking modules\n")

            with open("cookies.json", "r") as file:
                cookies = {}
                elems = json.loads(file.read())
                for cookie in elems:
                    for item in cookie.split("; "):
                        if "=" in item:
                            key, value = item.split("=", 1)
                            cookies[key] = value
                        else:
                            cookies[item] = True

            if args.modules != []:
                for module_class in args.modules:
                    module_setup(
                        module_class, base_url, proxies, cookies, filtered_data, args
                    )

            logger.info("Merging together the results from the scan")
            xss_df = pd.read_csv(DF + f"{base_url}_xss.csv")
            sql_df = pd.read_csv(DF + f"{base_url}_sqli.csv")
            csrf_df = pd.read_csv(DF + f"{base_url}_csrf.csv")
            path_traversal_df = pd.read_csv(DF + f"{base_url}_path_traversal.csv")
            merged_df = (
                xss_df.merge(sql_df[["URL", "SQLi"]], on="URL", how="left")
                .merge(csrf_df[["URL", "CSRF"]], on="URL", how="left")
                .merge(
                    path_traversal_df[["URL", "Path_Traversal"]], on="URL", how="left"
                )
            )
            logger.info(f"Saving infographics relative to the scan results in {IMG}")
            analysis = VulnerabilityAnalysis(base_url, merged_df)
            analysis.save_vulnerability_distribution(
                IMG + f"{base_url}_vulnerabilities_distribution.png"
            )
            analysis.save_http_methods_distribution(
                IMG + f"{base_url}_http_methods_distribution.png"
            )
            analysis.save_vulnerable_get_params(
                IMG + f"{base_url}_vulnerable_get_params.png"
            )
            analysis.save_vulnerable_post_params(
                IMG + f"{base_url}_vulnerable_post_params.png"
            )
        logger.info("Shutting down the program. Ciao!")
        sys.exit(0)
    except KeyboardInterrupt:
        logger.warning("KeyboardInterrupt detected! Stopping the execution.")
        sys.exit(0)

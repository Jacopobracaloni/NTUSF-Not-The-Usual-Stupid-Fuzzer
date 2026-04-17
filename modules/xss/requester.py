import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings
from requests import HTTPError
import logging
import sys
from modules.logger_config import setup_logger

logger = setup_logger(__name__)

warnings.filterwarnings("ignore")  # Disable SSL related warnings


def requester(url, data, GET, delay, timeout, proxies, cookies):
    headers = {}
    time.sleep(delay)
    user_agents = [
        "Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
    ]
    if "User-Agent" not in headers:
        headers["User-Agent"] = random.choice(user_agents)
    elif headers["User-Agent"] == "$":
        headers["User-Agent"] = random.choice(user_agents)
    try:
        if GET:
            response = requests.get(
                url,
                params=data,
                headers=headers,
                timeout=timeout,
                verify=False,
                proxies=proxies,
                cookies=cookies,
            )
        else:
            response = requests.post(
                url,
                data=data,
                headers=headers,
                timeout=timeout,
                verify=False,
                proxies=proxies,
                cookies=cookies,
            )
        return response
    except ProtocolError:
        logger.error("WAF is dropping suspicious requests.")
        logger.error("Scanning will continue after 10 minutes.")
        time.sleep(600)
    except Exception as e:
        logger.error("Unable to connect to the target.")
        return requests.Response()

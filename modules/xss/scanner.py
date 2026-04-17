import copy
import re
from modules.xss.config import xsschecker
from modules.xss.filterChecker import filterChecker
from modules.xss.generator import generator
from modules.xss.htmlParser import htmlParser
from modules.xss.requester import requester
from modules.xss.dom import dom
from modules.logger_config import setup_logger

logger = setup_logger(__name__)


def scan(
    url,
    GET,
    params,
    delay,
    timeout,
    proxies,
    cookies,
):
    checkedDOMs = []
    for paramName in params.keys():
        paramsCopy = copy.deepcopy(params)
        paramsCopy[paramName] = xsschecker
        response = requester(
            url,
            paramsCopy,
            GET,
            delay,
            timeout,
            proxies=proxies,
            cookies=cookies,
        )
        highlighted = dom(response)
        clean_highlighted = "".join(
            [re.sub(r"^\d+\s+", "", line) for line in highlighted]
        )
        if highlighted and clean_highlighted not in checkedDOMs:
            checkedDOMs.append(clean_highlighted)
            logger.info("Potentially vulnerable objects found at %s" % url)
            for line in highlighted:
                logger.info(line)
        occurences = htmlParser(response)
        occurences = filterChecker(
            url,
            paramsCopy,
            GET,
            delay,
            occurences,
            timeout,
            proxies=proxies,
            cookies=cookies,
        )
        vectors = generator(occurences, response.text)
        if vectors:
            for _, vects in vectors.items():
                try:
                    payload = list(vects)[0]
                    logger.info(
                        "Vulnerable webpage: %s\nVulnerable parameter: %s, with payload: %s\n"
                        % (url, paramName, payload)
                    )
                    return url
                except IndexError:
                    pass

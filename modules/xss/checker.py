import copy
from fuzzywuzzy import fuzz
import re

from modules.xss.config import xsschecker
from modules.xss.requester import requester
from modules.xss.utils import replaceValue, fillHoles


def checker(url, params, GET, delay, payload, positions, timeout, proxies, cookies):
    checkString = "st4r7s" + payload + "3nd"
    response = requester(
        url,
        replaceValue(params, xsschecker, checkString, copy.deepcopy),
        GET,
        delay,
        timeout,
        proxies,
        cookies,
    ).text.lower()
    reflectedPositions = []
    for match in re.finditer("st4r7s", response):
        reflectedPositions.append(match.start())
    filledPositions = fillHoles(positions, reflectedPositions)
    #  Itretating over the reflections
    num = 0
    efficiencies = []
    for position in filledPositions:
        allEfficiencies = []
        try:
            reflected = response[
                reflectedPositions[num] : reflectedPositions[num] + len(checkString)
            ]
            efficiency = fuzz.partial_ratio(reflected, checkString.lower())
            allEfficiencies.append(efficiency)
        except IndexError:
            pass
        if position:
            reflected = response[position : position + len(checkString)]
            efficiency = fuzz.partial_ratio(reflected, checkString)
            if reflected[:-2] == (
                "\\%s" % checkString.replace("st4r7s", "").replace("3nd", "")
            ):
                efficiency = 90
            allEfficiencies.append(efficiency)
            efficiencies.append(max(allEfficiencies))
        else:
            efficiencies.append(0)
        num += 1
    return list(filter(None, efficiencies))

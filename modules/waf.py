import json
import re
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def wafDetector(url):
    with open(sys.path[0] + "/modules/waf.json", "r") as file:
        file_content = file.read()
        if not file_content.strip():
            print("File is empty!")
            sys.exit(1)
        wafSignatures = json.loads(file_content)
    noise = '?xss=<script>alert("XSS")</script>'
    url += noise
    user_agent = "Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0"
    headers = {"User-Agent": user_agent}
    response = requests.get(
        url,
        headers=headers,
        timeout=20.0,
        verify=False,
        allow_redirects=False,
    )
    page = response.text
    code = str(response.status_code)
    headers = response.headers
    if headers.get("Server"):
        server = headers.get("Server")
    headers = str(headers)

    if int(code) >= 400:
        bestMatch = [0, None]
        for wafName, wafSignature in wafSignatures.items():
            score = 0
            pageSign = wafSignature["page"]
            codeSign = wafSignature["code"]
            headersSign = wafSignature["headers"]
            if pageSign:
                if re.search(pageSign, page, re.I):
                    score += 1
            if codeSign:
                if re.search(codeSign, code, re.I):
                    score += 0.5
            if headersSign:
                if re.search(headersSign, headers, re.I):
                    score += 1
            if score > bestMatch[0]:
                del bestMatch[:]
                bestMatch.extend([score, wafName])
        if bestMatch[0] != 0:
            return bestMatch[1], server
        else:
            return None, None
    else:
        return None, None

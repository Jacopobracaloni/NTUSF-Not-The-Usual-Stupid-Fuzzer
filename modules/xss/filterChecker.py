from modules.xss.checker import checker


def filterChecker(url, params, GET, delay, occurences, timeout, proxies, cookies):
    positions = occurences.keys()
    sortedEfficiencies = {}
    # adding < > to environments anyway because they can be used in all contexts
    environments = set(["<", ">"])
    for i in range(len(positions)):
        sortedEfficiencies[i] = {}
    for i in occurences:
        occurences[i]["score"] = {}
        context = occurences[i]["context"]
        if context == "comment":
            environments.add("-->")
        elif context == "script":
            environments.add(occurences[i]["details"]["quote"])
            environments.add("</scRipT/>")
        elif context == "attribute":
            if occurences[i]["details"]["type"] == "value":
                if (
                    occurences[i]["details"]["name"] == "srcdoc"
                ):  # srcdoc attribute accepts html data with html entity encoding
                    environments.add("&lt;")  # so let's add the html entity
                    environments.add("&gt;")  # encoded versions of < and >
            if occurences[i]["details"]["quote"]:
                environments.add(occurences[i]["details"]["quote"])
    for environment in environments:
        if environment:
            efficiencies = checker(
                url,
                params,
                GET,
                delay,
                environment,
                positions,
                timeout,
                proxies=proxies,
                cookies=cookies,
            )
            efficiencies.extend([0] * (len(occurences) - len(efficiencies)))
            for occurence, efficiency in zip(occurences, efficiencies):
                occurences[occurence]["score"][environment] = efficiency
    return occurences

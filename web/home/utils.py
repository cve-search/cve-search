import re
from html import escape

from flask import request
from flask_login import current_user

from lib.Config import Configuration
from lib.Toolkit import tk_compile
from sbin.db_blacklist import insertBlacklist
from sbin.db_whitelist import insertWhitelist
from web.helpers.common import timestringTOdatetime

config = Configuration()

defaultFilters = {
    "timeSelect": "all",
    "startDate": "",
    "endDate": "",
    "timeTypeSelect": "modified",
    "cvssSelect": "all",
    "cvss": "0",
    "rejectedSelect": "hide",
}

config_args = {
    "pageLength": config.getPageLength(),
    "listLogin": config.listLoginRequired(),
    "minimal": True,
}


def addCPEToList(cpe, listType, cpeType=None):
    def addCPE(cpe, cpeType, funct):
        return True if funct(cpe, cpeType) else False

    if not cpeType:
        cpeType = "cpe"

    if listType.lower() in ("blacklist", "black", "b", "bl"):
        return addCPE(cpe, cpeType, insertBlacklist)
    if listType.lower() in ("whitelist", "white", "w", "wl"):
        return addCPE(cpe, cpeType, insertWhitelist)


def list_mark(listed, cveList):
    from lib.DatabaseLayer import getRules

    if listed not in ["white", "black"]:
        return list(cveList)
    items = tk_compile(getRules(listed + "list"))
    # check the cpes (full or partially) in the black/whitelist
    for i, cve in enumerate(
        list(cveList)
    ):  # the list() is to ensure we don't have a pymongo cursor object
        for c in cve["vulnerable_configuration"]:
            if any(regex.match(c) for regex in items):
                cveList[i][listed + "listed"] = "yes"
    return cveList


def generate_minimal_query(f):
    query = []
    # retrieving lists
    if f["rejectedSelect"] == "hide":
        query.append(
            {
                "summary": re.compile(
                    r"^(?!\*\* REJECT \*\*\s+DO NOT USE THIS CANDIDATE NUMBER.*)"
                )
            }
        )

    # cvss score logic
    if "cvssVersion" in f:
        if f["cvssVersion"] == "V4":
            cvss_filter_field = "cvss4"
        elif f["cvssVersion"] == "V3":
            cvss_filter_field = "cvss3"
        else:
            cvss_filter_field = "cvss"
    else:
        cvss_filter_field = "cvss3"

    if f["cvssSelect"] == "above":
        query.append({cvss_filter_field: {"$gt": float(f["cvss"])}})
    elif f["cvssSelect"] == "equals":
        query.append({cvss_filter_field: float(f["cvss"])})
    elif f["cvssSelect"] == "below":
        query.append({cvss_filter_field: {"$lt": float(f["cvss"])}})

    # date logic
    if f["timeSelect"] != "all":
        if f["startDate"]:
            startDate = timestringTOdatetime(f["startDate"])
        if f["endDate"]:
            endDate = timestringTOdatetime(f["endDate"])

        if f["timeSelect"] == "from":
            query.append({f["timeTypeSelect"]: {"$gt": startDate}})
        elif f["timeSelect"] == "until":
            query.append({f["timeTypeSelect"]: {"$lt": endDate}})
        elif f["timeSelect"] == "between":
            query.append({f["timeTypeSelect"]: {"$gt": startDate, "$lt": endDate}})
        elif f["timeSelect"] == "outside":
            query.append(
                {
                    "$or": [
                        {f["timeTypeSelect"]: {"$lt": startDate}},
                        {f["timeTypeSelect"]: {"$gt": endDate}},
                    ]
                }
            )
    return query


def generate_full_query(f):
    from lib.DatabaseLayer import getRules

    query = generate_minimal_query(f)
    if current_user.is_authenticated:
        if f["blacklistSelect"] == "on":
            regexes = getRules("blacklist")
            if len(regexes) != 0:
                exp = "^(?!" + "|".join(regexes) + ")"
                query.append(
                    {
                        "$or": [
                            {"vulnerable_configuration": re.compile(exp)},
                            {"vulnerable_configuration": {"$exists": False}},
                            {"vulnerable_configuration": []},
                        ]
                    }
                )
        if f["whitelistSelect"] == "hide":
            regexes = getRules("whitelist")
            if len(regexes) != 0:
                exp = "^(?!" + "|".join(regexes) + ")"
                query.append(
                    {
                        "$or": [
                            {"vulnerable_configuration": re.compile(exp)},
                            {"vulnerable_configuration": {"$exists": False}},
                            {"vulnerable_configuration": []},
                        ]
                    }
                )
        if f["unlistedSelect"] == "hide":
            wlregexes = tk_compile(getRules("whitelist"))
            blregexes = tk_compile(getRules("blacklist"))
            query.append(
                {
                    "$or": [
                        {"vulnerable_configuration": {"$in": wlregexes}},
                        {"vulnerable_configuration": {"$in": blregexes}},
                    ]
                }
            )
    return query


def filter_logic(filters, skip, limit=None):
    from lib.DatabaseLayer import getCVEs

    query = generate_full_query(filters)
    limit = limit if limit else config_args["pageLength"]
    cve = getCVEs(limit=limit, skip=skip, query=query)
    # marking relevant records
    if current_user.is_authenticated:
        if filters["whitelistSelect"] == "on":
            cve["results"] = list_mark("white", cve["results"])
        if filters["blacklistSelect"] == "mark":
            cve["results"] = list_mark("black", cve["results"])
    return cve


def getFilterSettingsFromPost(r):
    from lib.DatabaseLayer import getCVEs

    filters = dict(request.form)
    errors = False
    # retrieving data
    try:
        cve = filter_logic(filters, r)
    except Exception:
        cve = getCVEs(limit=config_args["pageLength"], skip=r)
        errors = True
    return {"filters": filters, "cve": cve, "errors": errors}


def markCPEs(cve):
    from lib.DatabaseLayer import getRules

    blacklist = tk_compile(getRules("blacklist"))
    whitelist = tk_compile(getRules("whitelist"))

    for conf in cve["vulnerable_configuration"]:
        conf["list"] = "none"
        conf["match"] = "none"
        for w in whitelist:
            if w.match(conf["id"]):
                conf["list"] = "white"
                conf["match"] = w
        for b in blacklist:
            if b.match(conf["id"]):
                conf["list"] = "black"
                conf["match"] = b
    return cve


def filterUpdateField(data):
    if not data:
        return data
    returnvalue = []
    for line in data.split("\n"):
        if (
            not line.startswith("[+]Success to create index")
            and not line == "Not modified"
            and not line.startswith("Starting")
        ):
            returnvalue.append(line)
    return "\n".join(returnvalue)


def validateFilter(filter_params):
    # CVSS must be a number betreen 0 and 10.
    try:
        cvss = float(filter_params["cvss"])
        if cvss > 10:
            return False
        if cvss < 0:
            return False
    except ValueError:
        return False

    # Require valid options for selections.
    if filter_params["cvssSelect"] not in ["all", "above", "equals", "below"]:
        return False
    if filter_params["cvssVersion"] not in ["V2", "V3", "V4"]:
        return False
    if filter_params["rejectedSelect"] not in ["hide", "show"]:
        return False
    if filter_params["timeSelect"] not in [
        "all",
        "from",
        "until",
        "between",
        "outside",
    ]:
        return False
    if filter_params["timeTypeSelect"] not in [
        "modified",
        "published",
        "lastModified",
    ]:
        return False
    if filter_params["blacklistSelect"] not in ["on", "off", "mark"]:
        return False
    if filter_params["whitelistSelect"] not in ["on", "off", "hide"]:
        return False
    if filter_params["unlistedSelect"] not in ["hide", "show"]:
        return False

    # Validate dates: required values and reasonable ranges.
    if filter_params["timeSelect"] in ["from", "between", "outside"]:
        startDate = timestringTOdatetime(filter_params["startDate"])
        if not startDate:
            return False
    if filter_params["timeSelect"] in ["until", "between", "outside"]:
        endDate = timestringTOdatetime(filter_params["endDate"])
        if not endDate:
            return False
    if filter_params["timeSelect"] in ["between", "outside"]:
        if startDate > endDate:
            return False

    # None of the tests failed.
    return True


def SanitizeUserInput(filter_params):
    """
    Method to sanitize user input

    :param filter_params: Dictionary with filter params
    :type filter_params: dict
    :return: Sanitized filter params
    :rtype: dict
    """

    for each in filter_params:
        filter_params[each] = escape(filter_params[each])

    return filter_params


def adminInfo(output=None):
    from lib.DatabaseLayer import getDBStats

    return {"stats": getDBStats(True), "updateOutput": filterUpdateField(output)}


def parse_headers(headers):
    ret_dict = {}

    for key, val in headers.items():
        ret_dict[key] = val

    return ret_dict

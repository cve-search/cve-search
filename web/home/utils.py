import re

from flask import request
from flask_login import current_user

from lib.Config import Configuration
from lib.PluginManager import PluginManager
from lib.Toolkit import tk_compile
from lib.DatabaseLayer import (
    getRules,
    getCVEs,
    getDBStats,
)

from dateutil.parser import parse as parse_datetime

from sbin.db_blacklist import insertBlacklist
from sbin.db_whitelist import insertWhitelist

config = Configuration()

plugManager = PluginManager()
plugManager.loadPlugins()

defaultFilters = {
    "timeSelect": "all",
    "startDate": "",
    "endDate": "",
    "timeTypeSelect": "Modified",
    "cvssSelect": "all",
    "cvss": "0",
    "rejectedSelect": "hide",
}

config_args = {
    "pageLength": config.getPageLength(),
    "listLogin": config.listLoginRequired(),
    "minimal": True,
}

pluginArgs = {
    "current_user": current_user,
    "plugin_manager": plugManager,
}


def get_plugins():
    if (
        not current_user.is_authenticated
    ):  # Don't show plugins requiring auth if not authenticated
        plugins = [
            {"name": x.getName(), "link": x.getUID()}
            for x in plugManager.getWebPluginsWithPage(**pluginArgs)
            if not x.requiresAuth
        ]
    else:
        plugins = [
            {"name": x.getName(), "link": x.getUID()}
            for x in plugManager.getWebPluginsWithPage(**pluginArgs)
        ]
    return plugins


def get_cve_actions(cve):
    if (
        not current_user.is_authenticated
    ):  # Don't show actions requiring auth if not authenticated
        actions = [
            x for x in plugManager.getCVEActions(cve, **pluginArgs) if not x["auth"]
        ]
    else:
        actions = plugManager.getCVEActions(cve, **pluginArgs)
    return actions


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

    # cvss / cvss3 logic
    if f["cvssVersion"] == "V2":
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
            startDate = parse_datetime(f["startDate"], ignoretz=True, dayfirst=True)
        if f["endDate"]:
            endDate = parse_datetime(f["endDate"], ignoretz=True, dayfirst=True)

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
    query = generate_full_query(filters)
    limit = limit if limit else config_args["pageLength"]
    cve = getCVEs(limit=limit, skip=skip, query=query)
    # marking relevant records
    if current_user.is_authenticated:
        if filters["whitelistSelect"] == "on":
            cve["results"] = list_mark("white", cve["results"])
        if filters["blacklistSelect"] == "mark":
            cve["results"] = list_mark("black", cve["results"])
    plugManager.mark(cve, **pluginArgs)
    return cve


def getFilterSettingsFromPost(r):
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


def adminInfo(output=None):
    return {
        "stats": getDBStats(True),
        "plugins": plugManager.getPlugins(),
        "updateOutput": filterUpdateField(output),
    }


def parse_headers(headers):

    ret_dict = {}

    for key, val in headers.items():
        ret_dict[key] = val

    return ret_dict

import re
from html import escape
from flask import request
from lib.Config import Configuration
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
    "minimal": True,
}


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


def filter_logic(filters, skip, limit=None):
    from lib.DatabaseLayer import getCVEs

    query = generate_minimal_query(filters)
    limit = limit if limit else config_args["pageLength"]
    cve = getCVEs(limit=limit, skip=skip, query=query)
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

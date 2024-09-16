#!/usr/bin/env python3
#
# search is the search component of cve-search querying the MongoDB database.
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2012       Wim Remes
# Copyright (c) 2012-2018  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse

from bson import json_util
from dicttoxml import dicttoxml

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.DatabaseLayer import cvesForCPE, getCVEs, getFreeText, getCVEIDs, searchCVE
from lib.CVEs import CveHandler
from lib.cpe_conversion import split_cpe_name


# init control variables
csvOutput = 0
htmlOutput = 0
jsonOutput = 0
xmlOutput = 0
last_ndays_published = 0
last_ndays_modified = 0
nlimit = 0

# init various variables :-)
vSearch = ""
vOutput = ""
vFreeSearch = ""
summary_text = ""


# parse command-line arguments
argParser = argparse.ArgumentParser(
    description="Search for vulnerabilities in the National Vulnerability DB. Data from http://nvd.nist.org."
)
argParser.add_argument(
    "-p",
    type=str,
    nargs="+",
    help="P = search one or more products, e.g. o:microsoft:windows_7 or o:cisco:ios:12.1 or o:microsoft:windows_7 "
    "o:cisco:ios:12.1. Add --only-if-vulnerable if only vulnerabilities that directly affect the product are "
    "wanted.",
)
argParser.add_argument(
    "--only-if-vulnerable",
    dest="vulnProdSearch",
    default=False,
    action="store_true",
    help='With this option, "-p" will only return vulnerabilities directly assigned to the product. I.e. it will not '
    'consider "windows_7" if it is only mentioned as affected OS in an adobe:reader vulnerability. ',
)
argParser.add_argument(
    "--strict_vendor_product",
    dest="strict_vendor_product",
    default=False,
    action="store_true",
    help='With this option, a strict vendor product search is executed. The values in "-p" should be formatted as '
    "vendor:product, e.g. microsoft:windows_7",
)
argParser.add_argument(
    "--lax",
    default=False,
    action="store_true",
    help="Strict search for software version is disabled. Likely gives false positives for earlier versions that "
    "were not yet vulnerable. Note that version comparison for non-numeric values is done with simplifications.",
)
argParser.add_argument(
    "-f", type=str, help="F = free text search in vulnerability summary"
)
argParser.add_argument("-c", action="append", help="search one or more CVE-ID")
argParser.add_argument(
    "-o", type=str, help="O = output format [csv|html|json|xml|cveid]"
)
argParser.add_argument("-l", action="store_true", help="sort in descending mode")
argParser.add_argument(
    "-n",
    action="store_true",
    help="lookup complete cpe (Common Platform Enumeration) name for vulnerable configuration",
)
argParser.add_argument(
    "-r", action="store_true", help="lookup ranking of vulnerable configuration"
)
argParser.add_argument(
    "-a",
    default=False,
    action="store_true",
    help="Lookup CAPEC for related CWE weaknesses",
)
argParser.add_argument("-v", type=str, help="vendor name to lookup in reference URLs")
argParser.add_argument("-s", type=str, help="search in summary text")
argParser.add_argument("-t", type=int, help="search in last n day (published)")
argParser.add_argument("-T", type=int, help="search in last n day (modified)")
argParser.add_argument(
    "-i",
    default=False,
    type=int,
    help="Limit output to n elements (default: unlimited)",
)
argParser.add_argument(
    "-q",
    type=str,
    nargs="?",
    const="removed",
    help="Removed. Was used to search pip requirements file for CVEs.",
)
args = argParser.parse_args()

vSearch = args.p
relaxSearch = args.lax
strict_vendor_product = args.strict_vendor_product
vulnerableProductSearch = args.vulnProdSearch
cveSearch = [x.upper() for x in args.c] if args.c else None
vOutput = args.o
vFreeSearch = args.f
sLatest = args.l
namelookup = args.n
rankinglookup = args.r
capeclookup = args.a
last_ndays_published = args.t
last_ndays_modified = args.T
summary_text = args.s
nlimit = args.i

cves = CveHandler(
    rankinglookup=rankinglookup, namelookup=namelookup, capeclookup=capeclookup
)


def print_job(item):
    if csvOutput:
        printCVE_csv(item)
    elif htmlOutput:
        printCVE_html(item)
    # bson straight from the MongoDB db - converted to JSON default
    # representation
    elif jsonOutput:
        printCVE_json(item)
    elif xmlOutput:
        printCVE_xml(item)
    elif cveidOutput:
        printCVE_id(item)
    else:
        printCVE_human(item)


def search_product(prod):
    if strict_vendor_product:
        search = split_cpe_name(prod)
        search = (search[0], search[1])
        ret = cvesForCPE(
            search,
            lax=relaxSearch,
            vulnProdSearch=vulnerableProductSearch,
            strict_vendor_product=True,
        )
    else:
        ret = cvesForCPE(prod, lax=relaxSearch, vulnProdSearch=vulnerableProductSearch)
    if "notices" in ret:
        for notice in ret["notices"]:
            print(f"{notice}")
        print()  # Empty line to separate the notices from the results.
    for item in ret["results"]:
        if not last_ndays_published and not last_ndays_modified:
            print_job(item)
        else:
            if last_ndays_published:
                date_published_n_days_ago = datetime.now() - timedelta(
                    days=last_ndays_published
                )
                if item["published"] > date_published_n_days_ago:
                    print_job(item)
                    continue  # Do not show the item twice if both -t and -T are used.
            if last_ndays_modified:
                date_modified_n_days_ago = datetime.now() - timedelta(
                    days=last_ndays_modified
                )
                if item["modified"] > date_modified_n_days_ago:
                    print_job(item)


def vuln_config(entry):
    if not namelookup:
        return entry
    else:
        return cves.getcpe(cpeid=entry)


def is_number(s):
    try:
        ret = float(s)
        return ret
    except ValueError:
        return False


if args.q:
    print(
        "Support for -q (search pip requirements file for CVEs) has been removed",
        file=sys.stderr,
    )
    sys.exit(1)


# define which output to generate.
if vOutput == "csv":
    csvOutput = 1
elif vOutput == "html":
    htmlOutput = 1
elif vOutput == "xml":
    xmlOutput = 1
    from xml.etree.ElementTree import Element, tostring

    r = Element("cve-search")
elif vOutput == "json":
    jsonOutput = 1
elif vOutput == "cveid":
    cveidOutput = 1
else:
    cveidOutput = False

# Print first line of html output
if htmlOutput and args.p is not None:
    print("<html><body><h1>CVE search " + str(args.p) + " </h1>")
elif htmlOutput and args.c is not None:
    print("<html><body><h1>CVE-ID " + str(args.c) + " </h1>")

# search default is ascending mode
sorttype = 1
if sLatest:
    sorttype = -1


def printCVE_json(item, indent=None):
    date_fields = ["cvssTime", "modified", "published"]
    for field in date_fields:
        if field in item:
            item[field] = str(item[field])
    if not namelookup and not rankinglookup and not capeclookup:
        print(
            json.dumps(item, sort_keys=True, default=json_util.default, indent=indent)
        )
    else:
        if "vulnerable_configuration" in item:
            vulconf = []
            ranking = []
            for conf in item["vulnerable_configuration"]:
                if namelookup:
                    vulconf.append(cves.getcpe(cpeid=conf))
                if rankinglookup:
                    rank = cves.getranking(cpeid=conf)
                    if rank and rank not in ranking:
                        ranking.append(rank)
            if namelookup:
                item["vulnerable_configuration"] = vulconf
            if rankinglookup:
                item["ranking"] = ranking
            if "cwe" in item and capeclookup:
                if item["cwe"].lower() != "unknown":
                    item["capec"] = cves.getcapec(cweid=(item["cwe"].split("-")[1]))
            print(
                json.dumps(
                    item, sort_keys=True, default=json_util.default, indent=indent
                )
            )


def printCVE_html(item):
    print(
        "<h2>"
        + item["id"]
        + "<br></h2>CVSS score: "
        + (str(item["cvss"]) if "cvss" in item else "None")
        + "<br>"
        + "<b>"
        + str(item["published"])
        + "<b><br>"
        + item["summary"]
        + "<br>"
    )
    print("References:<br>")
    for entry in item["references"]:
        print(entry + "<br>")

    ranking = []
    for entry in item["vulnerable_configuration"]:
        if rankinglookup:
            rank = cves.getranking(cpeid=entry)
            if rank and rank not in ranking:
                ranking.append(rank)
    if rankinglookup:
        print("Ranking:<br>")
        for ra in ranking:
            for e in ra:
                for i in e:
                    print(i + ": " + str(e[i]) + "<br>")
    print("<hr><hr>")


def printCVE_csv(item):
    # We assume that the vendor name is usually in the hostame of the
    # URL to avoid any match on the resource part
    refs = []
    for entry in item["references"]:
        if args.v is not None:
            url = urlparse(entry)
            hostname = url.netloc
            if re.search(args.v, hostname):
                refs.append(entry)
    if not refs:
        refs = "[no vendor link found]"
    if namelookup:
        nl = " ".join(item["vulnerable_configuration"])
    ranking = []
    ranking_ = []
    for entry in item["vulnerable_configuration"]:
        if rankinglookup:
            rank = cves.getranking(cpeid=entry)
            if rank and rank not in ranking:
                ranking.append(rank)
    if rankinglookup:
        for r in ranking:
            for e in r:
                for i in e:
                    ranking_.append(i + ":" + str(e[i]))
        if not ranking_:
            ranking_ = "[No Ranking Found]"
        else:
            ranking_ = " ".join(ranking_)

    csvoutput = csv.writer(
        sys.stdout, delimiter="|", quotechar="|", quoting=csv.QUOTE_MINIMAL
    )
    if not rankinglookup:
        if not namelookup:
            csvoutput.writerow(
                [
                    item["id"],
                    str(item["published"]),
                    item["cvss"] if ("cvss" in item) else "None",
                    item["summary"],
                    refs,
                ]
            )
        else:
            csvoutput.writerow(
                [
                    item["id"],
                    str(item["published"]),
                    item["cvss"] if ("cvss" in item) else "None",
                    item["summary"],
                    refs,
                    nl,
                ]
            )
    else:
        if not namelookup:
            csvoutput.writerow(
                [
                    item["id"],
                    str(item["published"]),
                    item["cvss"] if ("cvss" in item) else "None",
                    item["summary"],
                    refs,
                    ranking_,
                ]
            )
        else:
            csvoutput.writerow(
                [
                    item["id"],
                    str(item["published"]),
                    item["cvss"] if ("cvss" in item) else "None",
                    item["summary"],
                    refs,
                    nl,
                    ranking_,
                ]
            )


def printCVE_xml(item):
    xml = dicttoxml(item)
    print(xml.decode("utf-8"))


def printCVE_id(item):
    print(item["id"])


def printCVE_human(item):
    print("CVE\t: {}".format(item["id"]))
    print("DATE\t: {}".format(str(item["published"])))
    print("CVSS\t: {}".format((str(item["cvss"]) if "cvss" in item else "None")))
    print(item["summary"])
    print("\nReferences:")
    print("-----------")
    for entry in item["references"]:
        print(entry)
    print("\nVulnerable Configs:")
    print("-------------------")
    ranking = []
    if "vulnerable_configuration" in item:
        for entry in item["vulnerable_configuration"]:
            print(vuln_config(entry))
            if rankinglookup:
                rank = cves.getranking(cpeid=entry)
                if rank and rank not in ranking:
                    ranking.append(rank)
    else:
        print([])
    if rankinglookup:
        print("\nRanking: ")
        print("--------")
        for ra in ranking:
            for e in ra:
                for i in e:
                    print("{}: {}".format(i, str(e[i])))
    print("\n\n")


# Search in summary text
def search_in_summary(item):
    print(item["summary"])
    # if args.a in str(item['summary']):
    #  printCVE_json(item)


if cveSearch:
    for item in getCVEs(cves=cveSearch)["results"]:
        print_job(item)
    if htmlOutput:
        print("</body></html>")
    sys.exit(0)

# Basic freetext search (in vulnerability summary).
# Full-text indexing is more efficient to search across all CVEs.
if vFreeSearch:
    try:
        for item in getFreeText(vFreeSearch):
            printCVE_json(item, indent=2)
    except:
        sys.exit("Free text search not enabled on the database!")
    sys.exit(0)


# Search Product (best to use CPE notation, e.g. cisco:ios:12.2
if vSearch:
    # Search multiple products in one query
    for cpe in vSearch:
        search_product(cpe)
    if htmlOutput:
        print("</body></html>")
    sys.exit(0)

# Search text in summary
if summary_text:
    listCve = searchCVE(
        find_params={"summary": re.compile(summary_text, re.IGNORECASE)}, limit=nlimit
    )
    for item in listCve:
        item = cves.getCveFromMongoDbDoc(item)

        if "cvss" in item:
            if type(item["cvss"]) == str:
                item["cvss"] = float(item["cvss"])
        date_fields = ["cvssTime", "modified", "published"]
        for field in date_fields:
            if field in item:
                item[field] = str(item[field])

        if not last_ndays_published and not last_ndays_modified:
            if vOutput:
                printCVE_id(item)
            else:
                print(json.dumps(item, sort_keys=True, default=json_util.default))
        else:
            if last_ndays_published:
                date_published_n_days_ago = datetime.now() - timedelta(
                    days=last_ndays_published
                )
                try:
                    if (
                        datetime.strptime(item["published"], "%Y-%m-%d %H:%M:%S.%f")
                        > date_published_n_days_ago
                    ):
                        if vOutput:
                            printCVE_id(item)
                        else:
                            print(
                                json.dumps(
                                    item, sort_keys=True, default=json_util.default
                                )
                            )
                            continue  # Do not show the item twice if both -t and -T are used.
                except:
                    pass
            if last_ndays_modified:
                date_modified_n_days_ago = datetime.now() - timedelta(
                    days=last_ndays_modified
                )
                try:
                    if (
                        datetime.strptime(item["published"], "%Y-%m-%d %H:%M:%S.%f")
                        > date_modified_n_days_ago
                    ):
                        if vOutput:
                            printCVE_id(item)
                        else:
                            print(
                                json.dumps(
                                    item, sort_keys=True, default=json_util.default
                                )
                            )
                except:
                    pass
    if htmlOutput:
        print("</body></html>")
    sys.exit(0)

if xmlOutput:
    # default encoding is UTF-8. Should this be detected on the terminal?
    s = tostring(r).decode("utf-8")
    print(s)
    sys.exit(0)

else:
    argParser.print_help()
    argParser.exit()

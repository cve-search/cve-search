#!/usr/bin/env python3
#
# search is the search component of cve-search querying the MongoDB database.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012 		Wim Remes
# Copyright (c) 2012-2015 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import re
import argparse
import csv
from urllib.parse import urlparse
import json
from bson import json_util

from lib import CVEs
import lib.DatabaseLayer as db

# init control variables
csvOutput = 0
htmlOutput = 0
jsonOutput = 0
xmlOutput = 0

# init various variables :-)
vSearch = ""
vOutput = ""
vFreeSearch = ""


# parse command-line arguments
argParser = argparse.ArgumentParser(description='Search for vulnerabilities in the National Vulnerability DB. Data from http://nvd.nist.org.')
argParser.add_argument('-p', type=str, help='S = search product, e.g. o:microsoft:windows_7 or o:cisco:ios:12.1')
argParser.add_argument('-f', type=str, help='F = free text search in vulnerability summary')
argParser.add_argument('-c', action='append', help='search one or more CVE-ID')
argParser.add_argument('-o', type=str, help='O = output format [csv|html|json|xml|cveid]')
argParser.add_argument('-l', action='store_true', help='sort in descending mode')
argParser.add_argument('-n', action='store_true', help='lookup complete cpe (Common Platform Enumeration) name for vulnerable configuration')
argParser.add_argument('-r', action='store_true', help='lookup ranking of vulnerable configuration')
argParser.add_argument('-a', default=False, action='store_true', help='Lookup CAPEC for related CWE weaknesses')
argParser.add_argument('-v', type=str, help='vendor name to lookup in reference URLs')
args = argParser.parse_args()
vSearch = args.p
cveSearch = [x.upper() for x in args.c] if args.c else None
vOutput = args.o
vFreeSearch = args.f
sLatest = args.l
namelookup = args.n
rankinglookup = args.r
capeclookup = args.a

cves = CVEs.last(rankinglookup=rankinglookup, namelookup=namelookup, capeclookup=capeclookup)

# replace special characters in vSearch with encoded version.
# Basically cuz I'm to lazy to handle conversion on DB creation ...
if vSearch:
    vSearch = re.sub(r'\(', '%28', vSearch)
    vSearch = re.sub(r'\)', '%29', vSearch)

# define which output to generate.
if vOutput == "csv":
    csvOutput = 1
elif vOutput == "html":
    htmlOutput = 1
elif vOutput == "xml":
    xmlOutput = 1
    from xml.etree.ElementTree import Element, SubElement, tostring
    from xml.sax.saxutils import escape as SaxEscape
    r = Element('cve-search')
elif vOutput == "json":
    jsonOutput = 1
elif vOutput == "cveid":
    cveidOutput = 1
else:
    cveidOutput = False

# Print first line of html output
if htmlOutput and args.p is not None:
    print("<html><body><h1>CVE search " + args.p + " </h1>")
elif htmlOutput and args.c is not None:
    print("<html><body><h1>CVE-ID " + str(args.c) + " </h1>")

# search default is ascending mode
sorttype = 1
if sLatest:
    sorttype = -1


def printCVE(item):
    if not namelookup and not rankinglookup and not capeclookup:
        print(json.dumps(item, sort_keys=True, default=json_util.default))
    else:
        if "vulnerable_configuration" in item:
            vulconf = []
            ranking = []
            for conf in item['vulnerable_configuration']:
                if namelookup:
                    vulconf.append(cves.getcpe(cpeid=conf))
                if rankinglookup:
                    rank = cves.getranking(cpeid=conf)
                    if rank and rank not in ranking:
                        ranking.append(rank)
            if namelookup:
                item['vulnerable_configuration'] = vulconf
            if rankinglookup:
                item['ranking'] = ranking
            if "cwe" in item and capeclookup:
                if item['cwe'].lower() != 'unknown':
                    item['capec'] = cves.getcapec(cweid=(item['cwe'].split('-')[1]))
            print(json.dumps(item, sort_keys=True, default=json_util.default))

if cveSearch:
    for cveid in db.getCVEs(cves=cveSearch):
        printCVE(cveid)
    sys.exit(0)
# Basic freetext search (in vulnerability summary).
# Full-text indexing is more efficient to search across all CVEs.
if vFreeSearch:
    try:
        for item in db.getFreeText(vFreeSearch):
            print(item)
    except:
        sys.exit("Free text search not enabled on the database!")
    sys.exit(0)

# Search Product (best to use CPE notation, e.g. cisco:ios:12.2
if vSearch:
    for item in db.cvesForCPE(vSearch):
        if csvOutput:
            # We assume that the vendor name is usually in the hostame of the
            # URL to avoid any match on the resource part
            refs = []
            for entry in item['references']:
                if args.v is not None:
                    url = urlparse(entry)
                    hostname = url.netloc
                    if re.search(args.v, hostname):
                        refs.append(entry)
            if not refs:
                refs = "[no vendor link found]"
            if namelookup:
                nl = " ".join(item['vulnerable_configuration'])
            csvoutput = csv.writer(sys.stdout, delimiter='|', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            if not namelookup:
                csvoutput.writerow([item['id'], item['Published'], item['cvss'], item['summary'], refs])
            else:
                csvoutput.writerow([item['id'], item['Published'], item['cvss'], item['summary'], refs, nl])
        elif htmlOutput:
            print("<h2>" + item['id'] + "<br></h2>CVSS score: " + str(item['cvss']) + "<br>" + "<b>" + item['Published'] + "<b><br>" + item['summary'] + "<br>")
            print("References:<br>")
            for entry in item['references']:
                print(entry + "<br>")
            print("<hr><hr>")
        # bson straight from the MongoDB db - converted to JSON default
        # representation
        elif jsonOutput:
            printCVE(item)
        elif xmlOutput:
            c = SubElement(r, 'id')
            c.text = item['id']
            c = SubElement(r, 'Published')
            c.text = item['Published']
            c = SubElement(r, 'cvss')
            c.text = str(item['cvss'])
            c = SubElement(r, 'summary')
            c.text = SaxEscape(item['summary'])
            for e in item['references']:
                c = SubElement(r, 'references')
                c.text = SaxEscape(e)
            for e in item['vulnerable_configuration']:
                c = SubElement(r, 'vulnerable_configuration')
                c.text = SaxEscape(e)
        elif cveidOutput:
            print(item['id'])
        else:
            print("CVE\t: " + item['id'])
            print("DATE\t: " + item['Published'])
            print("CVSS\t: " + str(item['cvss']))
            print(item['summary'])
            print("\nReferences:")
            print("-----------")
            for entry in item['references']:
                print(entry)
            print("\nVulnerable Configs:")
            print("-------------------")
            for entry in item['vulnerable_configuration']:
                if not namelookup:
                    print(entry)
                else:
                    print(cves.getcpe(cpeid=entry))
            print("\n\n")

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

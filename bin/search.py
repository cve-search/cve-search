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

from datetime import datetime, timedelta

# init control variables
csvOutput = 0
htmlOutput = 0
jsonOutput = 0
xmlOutput = 0
last_ndays = 0
nlimit = 0

    # init various variables :-)
vSearch = ""
vOutput = ""
vFreeSearch = ""
summary_text = ""


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
argParser.add_argument('-s', type=str, help='search in summary text')
argParser.add_argument('-t', type=int, help='search in last n day')
argParser.add_argument('-i', default=False, type=int, help='Limit output to n elements (default: unlimited)')
args = argParser.parse_args()

vSearch = args.p
cveSearch = [x.upper() for x in args.c] if args.c else None
vOutput = args.o
vFreeSearch = args.f
sLatest = args.l
namelookup = args.n
rankinglookup = args.r
capeclookup = args.a
last_ndays = args.t
summary_text= args.s
nlimit =args.i

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


def printCVE_json(item, indent=None):
    date_fields = ['cvss-time', 'Modified', 'Published']
    for field in date_fields:
        if field in item:
            item[field] = str(item[field])
    if not namelookup and not rankinglookup and not capeclookup:
        print(json.dumps(item, sort_keys=True, default=json_util.default, indent=indent))
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
            print(json.dumps(item, sort_keys=True, default=json_util.default, indent=indent))

def printCVE_html(item):
    print("<h2>" + item['id'] + "<br></h2>CVSS score: " + str(item['cvss']) + "<br>" + "<b>" + str(item['Published']) + "<b><br>" + item['summary'] + "<br>")
    print("References:<br>")
    for entry in item['references']:
        print(entry + "<br>")

    ranking =[]
    for entry in item['vulnerable_configuration']:
        if rankinglookup:
            rank = cves.getranking(cpeid=entry)
            if rank and rank not in ranking:
                    ranking.append(rank)
    if rankinglookup:
        print("Ranking:<br>")
        for ra in ranking:
            for e in ra:
                for i in e: 
                    print( i + ": " + str(e[i])+"<br>")
    print("<hr><hr>")

def printCVE_csv(item):
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
    ranking =[]
    ranking_=[]
    for entry in item['vulnerable_configuration']:
        if rankinglookup:
            rank = cves.getranking(cpeid=entry)
            if rank and rank not in ranking:
                    ranking.append(rank)
    if rankinglookup:
        for r in ranking:
            for e in r:
                for i in e:
                    ranking_.append(i+":"+str(e[i]))
        if not ranking_:
            ranking_="[No Ranking Found]"
        else:
            ranking_ = " ".join(ranking_)
                      
    csvoutput = csv.writer(sys.stdout, delimiter='|', quotechar='|', quoting=csv.QUOTE_MINIMAL)
    if not rankinglookup:
        if not namelookup:
            csvoutput.writerow([item['id'], str(item['Published']), item['cvss'], item['summary'], refs])
        else:
            csvoutput.writerow([item['id'], str(item['Published']), item['cvss'], item['summary'], refs, nl])
    else:
        if not namelookup:
            csvoutput.writerow([item['id'], str(item['Published']), item['cvss'], item['summary'], refs,ranking_])
        else:
            csvoutput.writerow([item['id'], str(item['Published']), item['cvss'], item['summary'], refs, nl,ranking_ ])
        
         
def printCVE_xml(item):
    c = SubElement(r, 'id')
    c.text = item['id']
    c = SubElement(r, 'Published')
    c.text = str(item['Published'])
    c = SubElement(r, 'cvss')
    c.text = str(item['cvss'])
    c = SubElement(r, 'summary')
    c.text = SaxEscape(item['summary'])
    for e in item['references']:
        c = SubElement(r, 'references')
        c.text = SaxEscape(e)
    ranking=[]    
    for e in item['vulnerable_configuration']:
        c = SubElement(r, 'vulnerable_configuration')
        c.text = SaxEscape(e)
        if rankinglookup:
            rank = cves.getranking(cpeid=e)
            if rank and rank not in ranking:
                    ranking.append(rank)
    if rankinglookup:
        for ra in ranking:
            for e in ra:
                for i in e:
                    c = SubElement(r, i)
                    c.text =str(e[i])           

def printCVE_id(item):
    print(item['id'])

def printCVE_human(item):
    print("CVE\t: " + item['id'])
    print("DATE\t: " + str(item['Published']))
    print("CVSS\t: " + str(item['cvss']))
    print(item['summary'])
    print("\nReferences:")
    print("-----------")
    for entry in item['references']:
        print(entry)
    print("\nVulnerable Configs:")
    print("-------------------")
    ranking=[]
    for entry in item['vulnerable_configuration']:
        
        if not namelookup:
            print(entry)
        else:
            print(cves.getcpe(cpeid=entry))
        if rankinglookup:
            rank = cves.getranking(cpeid=entry)
            if rank and rank not in ranking:
                    ranking.append(rank)
    if rankinglookup:
        print("\nRanking: ")
        print("--------")
        for ra in ranking:
            for e in ra:
                for i in e: 
                    print( i + ": " + str(e[i]))
    print("\n\n")

# Search in summary text
def search_in_summary(item):
     print(item['summary'])
     #if args.a in str(item['summary']):
      #  printCVE_json(item)

if cveSearch:
    for item in db.getCVEs(cves=cveSearch):
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


    if htmlOutput:
        print("</body></html>")
    sys.exit(0)

# Basic freetext search (in vulnerability summary).
# Full-text indexing is more efficient to search across all CVEs.
if vFreeSearch:
    try:
        for item in db.getFreeText(vFreeSearch):
            printCVE_json(item, indent=2)
    except:
        sys.exit("Free text search not enabled on the database!")
    sys.exit(0)


# Search Product (best to use CPE notation, e.g. cisco:ios:12.2
if vSearch:

    for item in db.cvesForCPE(vSearch):
        if not last_ndays:
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
        else:
            date_n_days_ago = datetime.now() - timedelta(days=last_ndays)
            if item['Published'] > date_n_days_ago: 

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
    if htmlOutput:
        print("</body></html>")
    sys.exit(0)

# Search text in summary 
if summary_text:
    import lib.CVEs as cves

    l = cves.last(rankinglookup=rankinglookup, namelookup=namelookup, capeclookup=capeclookup)

    for cveid in db.getCVEIDs(limit=nlimit):
        item = l.getcve(cveid=cveid)
        if 'cvss' in item:
            if type(item['cvss']) == str:
                item['cvss'] = float(item['cvss'])
        date_fields = ['cvss-time', 'Modified', 'Published']
        for field in date_fields:
            if field in item:
                item[field] = str(item[field])
        if summary_text.upper() in item['summary'].upper():
            if not last_ndays:
                if vOutput:
                    printCVE_id(item)
                else:
                    print(json.dumps(item, sort_keys=True, default=json_util.default))    
            else:

                date_n_days_ago = datetime.now() - timedelta(days=last_ndays)
                   # print(item['Published'])
                   # print(type (item['Published']))
                   # print("Last n day " +str(last_ndays)) 
                try:
                    if  datetime.strptime(item['Published'], '%Y-%m-%d %H:%M:%S.%f')  > date_n_days_ago:
                        if vOutput:
                            printCVE_id(item)
                        else:
                            print(json.dumps(item, sort_keys=True, default=json_util.default))
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
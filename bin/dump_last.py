#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Dump last CVE entries in RSS 1,RSS 2 or Atom format.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2015 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015      Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import time
import datetime
import argparse

import lib.CVEs as cves

argParser = argparse.ArgumentParser(description='Dump last CVE entries in RSS/Atom format or in HTML tables')
argParser.add_argument('-f', type=str, help='Output format (rss1,rss2,atom,html)', default='rss1')
argParser.add_argument('-l', type=int, help='Last n items (default:10)', default=10)
argParser.add_argument('-n', action='store_false', help='Disable lookup CPE name (default is True)')
argParser.add_argument('-r', action='store_true', help='Enable CVE ranking (default is False) and only print entries with ranking')
argParser.add_argument('-c', default=False, action='store_true', help='Display CAPEC values')

args = argParser.parse_args()

if args.l:
    last = args.l
else:
    last = 10

ref = "http://adulau.github.com/cve-search/"
cvelist = cves.last(rankinglookup=args.r, namelookup=args.n, capeclookup=args.c)

if not(args.f == "html"):
    from feedformatter import Feed
    feed = Feed()

    feed.feed['title'] = "cve-search Last " + str(last) + " CVE entries generated on " + str(datetime.datetime.now())
    feed.feed['link'] = "http://adulau.github.com/cve-search/"
    feed.feed['author'] = "Generated with cve-search available at http://adulau.github.com/cve-search/"
    feed.feed['description'] = ""
else:
    print ("<html><head>")
    print ("<style>.cve table { border-collapse: collapse; text-align: left; width: 100%; } .cve {font: normal 12px/150% Geneva, Arial, Helvetica, sans-serif; background: #fff; overflow: hidden; border: 1px solid #006699; -webkit-border-radius: 3px; -moz-border-radius: 3px; border-radius: 3px; }.cve table td, .cve table th { padding: 3px 10px; }.cve table tbody td { color: #00496B; border-left: 1px solid #E1EEF4;font-size: 12px;font-weight: normal; }.cve table tbody .alt td { background: #E1EEF4; color: #00496B; }.cve table tbody td:first-child { border-left: none; }.cve table tbody tr:last-child td { border-bottom: none; }.cve table tfoot td div { border-top: 1px solid #006699;background: #E1EEF4;} .cve table tfoot td { padding: 0; font-size: 12px } .cve table tfoot td div{ padding: 0px; }</style>")
    print ("<title>Last " + str(args.l) + " CVE entries</title>")
    print ("</head><body>")
for x in cvelist.get(limit=last):
    if not(args.f == "html"):
        item = {}
        item['title'] = str(x['id']) + " " + x['summary'][:90] + "..."
        item['description'] = x['summary']
        if args.r and x.get('ranking'):
            item['description'] = item['description'] + " Ranking:" + str(x['ranking'])
        item['pubDate'] = time.localtime()
        item['guid'] = x['id']
        if x['references']:
            item["link"] = str(x['references'][0])
        else:
            item["link"] = "http://web.nvd.nist.gov/view/vuln/detail?vulnId=" + x['id']
        feed.items.append(item)
    else:
        print ("<div class=\"cve\"><table><tbody>")
        print ("<tr class=\"alt\">")
        print ("<td>" + str(x['id']) + " - " + x['summary'][:90] + "...</td>")
        print ("</tr>")
        print ("<tr><td>CVSS: " + str(x['cvss']) + " Published: " + x['Published'] + "</td></tr>")
        print ("<tr>")
        print ("<td> Summary: " + x['summary'] + "</td>")
        print ("</tr>")
        print ("<tr><td>Vulnerable configuration:</td></tr>")
        print ("<tr><td><ul>")
        for v in x['vulnerable_configuration']:
            sys.stdout.write("<li>" + cvelist.getcpe(v) + "</li>")
        print ("</ul></td></tr>")
        if x.get('ranking'):
            print ("<tr><td>Ranking:" + str(x['ranking']) + "</td></tr>")
        print ("<tr><td>References:<td></tr>")
        print ("<tr><td><ul>")
        for r in x['references']:
            sys.stdout.write("<li><a href=\"" + str(r) + "\">" + str(r) + "</a></li>")
        print ("</ul></tr></td>")
        print ("</tbody></table></div><br/>")
if args.f == "rss1":
    print (feed.format_rss1_string())
elif args.f == "atom":
    print (feed.format_atom_string())
elif args.f == "html":
    print ("Generated with <a href=\"https://github.com/adulau/cve-search\">cve-search</a> at " + str(datetime.datetime.today()) + ".")
    print ("</body></html>")
else:
    print (feed.format_rss2_string())

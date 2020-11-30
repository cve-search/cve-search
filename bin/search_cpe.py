#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014       psychedelys
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com
# Copyright (c) 2015-2019  Alexandre Dulaunoy - a@foo.be

import argparse
import json
import os
import re
import sys
import urllib.parse

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import lib.DatabaseLayer as db

runPath = os.path.dirname(os.path.realpath(__file__))

vOutput = ""

argParser = argparse.ArgumentParser(description="Search for CPE with a pattern")
argParser.add_argument("-s", type=str, required=True, help="search in cpe list")
argParser.add_argument(
    "-o",
    type=str,
    default="expanded",
    help="O = output format [expanded, compact, json, csv] (default: expanded)",
)
argParser.add_argument(
    "-f",
    action="store_true",
    help="Enlarge the CPE search to all CPE indexed. Need the cpeother activated.",
    default=False,
)

args = argParser.parse_args()
cpeSearch = args.s
vOutput = args.o


def search(cpe):
    res = db.getCPEMatching(re.compile(cpe, re.IGNORECASE), args.f)

    if vOutput == "compact":
        for item in res:
            print("{}".format(item["id"]))
    elif vOutput == "expanded":
        for item in res:
            print("{} {}".format(item["id"], item["title"]))
    elif vOutput == "csv":
        for item in res:
            if "references" in item:
                ref = ",".join(item["references"])
                print("{},{},{}".format(item["id"], item["title"], ref))
            else:
                print("{},{}".format(item["id"], item["title"]))
    elif vOutput == "json":
        o = []
        for item in res:
            x = {}
            x["id"] = item["id"]
            x["title"] = item["title"]
            if "references" in item:
                x["references"] = item["references"]
            o.append(x)
        print(json.dumps(o, sort_keys=True, indent=4))


# replace special characters in cpeSearch with encoded version.
cpeSearch = urllib.parse.quote(cpeSearch)

search(cpeSearch)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014 	psychedelys
# Copyright (c) 2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import re
import argparse

from lib.Config import Configuration


runPath = os.path.dirname(os.path.realpath(__file__))

# connect to DB
db = Configuration.getMongoConnection()

vOutput = ""

argParser = argparse.ArgumentParser(description='Search for CPE with a pattern')
argParser.add_argument('-s', type=str, help='search in cpe list')
argParser.add_argument('-o', type=str, help='O = output format [compact]')
argParser.add_argument('-f', action='store_true', help='Enlarge the CPE search to all CPE indexed. Need the cpeother activated.', default=False)

args = argParser.parse_args()
cpeSearch = args.s
vOutput = args.o


def search(collection, cpe):
    res = collection.find({'id': {'$regex': re.compile(cpe, re.IGNORECASE)}})
    res.count()

    if vOutput == "compact":
        for item in res:
            print(item['id'])
    else:
        for item in res:
            print(item['id'] + "  " + item['title'])


if not cpeSearch:
    print ("no option provided")
    argParser.print_help()
else:
    # replace special characters in cpeSearch with encoded version.
    cpeSearch = re.sub(r'\(', '%28', cpeSearch)
    cpeSearch = re.sub(r'\)', '%29', cpeSearch)

    search(db.cpe, cpeSearch)

    if args.f:
        search(db.cpeother, cpeSearch)

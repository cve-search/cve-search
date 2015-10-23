#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tool to dump in JSON the database along with the associated ranking
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2015 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 		Pieter-Jan Moreels - pieterjan.moreels@gmail.com
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import argparse
import json
from bson import json_util

import lib.CVEs as cves
import lib.DatabaseLayer as db

argParser = argparse.ArgumentParser(description='Dump database in JSON format')
argParser.add_argument('-r', default=False, action='store_true', help='Include ranking value')
argParser.add_argument('-v', default=False, action='store_true', help='Include vfeed map')
argParser.add_argument('-c', default=False, action='store_true', help='Include CAPEC information')
argParser.add_argument('-l', default=False, type=int, help='Limit output to n elements (default: unlimited)')
args = argParser.parse_args()

rankinglookup = args.r
vfeedlookup = args.v
capeclookup = args.c

l = cves.last(rankinglookup=rankinglookup, vfeedlookup=vfeedlookup, capeclookup=capeclookup)

for cveid in db.getCVEIDs(limit=args.l):
    item = l.getcve(cveid=cveid)
    if 'cvss' in item:
        if type(item['cvss']) == str:
            item['cvss'] = float(item['cvss'])
    print (json.dumps(item, sort_keys=True, default=json_util.default))

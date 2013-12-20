#!/usr/bin/env python3.1
# -*- coding: utf-8 -*-
#
# Tool to dump in JSON the database along with the associated ranking
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2013 Alexandre Dulaunoy - a@foo.be

import sys
import argparse
import pymongo
import os
import json
from bson import json_util

sys.path.append("./lib/")
import cves

connect = pymongo.Connection()
db = connect.cvedb
collection = db.cves

def dumpallcveid ():
    cveid = []
    for x in collection.find({}).sort('_id',1):
        cveid.append(x['id'])
    return cveid

argParser = argparse.ArgumentParser(description='Dump database in JSON format')
argParser.add_argument('-r', action='store_true', help='Include ranking value')
argParser.add_argument('-v', action='store_true', help='Include vfeed map')
args = argParser.parse_args()

if args.r:
    rankinglookup=True
else:
    rankinglookup=False

if args.v:
    vfeedlookup=True
else:
    vfeedlookup=False

l = cves.last(rankinglookup=rankinglookup, vfeedlookup=vfeedlookup)

for cveid in dumpallcveid():
    item = l.getcve(cveid=cveid)
    print (json.dumps(item, sort_keys=True, default=json_util.default))

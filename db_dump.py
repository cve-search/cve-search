#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tool to dump in JSON the database along with the associated ranking
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2013 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 		Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Import
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, "./lib/"))

import pymongo

import argparse
import json
from bson import json_util

import cves
from Config import Configuration

# connect to db
db = Configuration.getMongoConnection()
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

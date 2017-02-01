#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Import of the VIA4 dataset (vFeed replacement)
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2016  Pieter-Jan Moreels
# Imports
import json
import os
import sys

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from dateutil.parser import parse as parse_datetime

from lib.Config import Configuration
import lib.DatabaseLayer as db

# To Do: Implement REDIS

try:
    redis = Configuration.getRedisRefConnection()
    try:
        redis.info()
    except:
        sys.exit("Redis server not running on %s:%s"%(Configuration.getRedisHost(),Configuration.getRedisPort()))
except Exception as e:
    print(e)
    sys.exit(1)

try:
    (f, r) = Configuration.getFeedData('via4')
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(Configuration.getFeedURL("via4")))

# check modification date
lastmodified = parse_datetime(r.headers['last-modified'], ignoretz=True)
i=db.getLastModified("via4")
if i is not None:
    if lastmodified == i:
        print("Not modified")
        sys.exit(0)

data = json.loads(f.read().decode('utf-8'))
cves = data['cves']
bulk = [dict(val, id=key) for key, val in cves.items() if key]
db.bulkUpdate('via4', bulk)
db.setColInfo('via4', 'sources',     data['metadata']['sources'])
db.setColInfo('via4', 'searchables', data['metadata']['searchables'])

#update database info after successful program-run
db.setColUpdate('via4', lastmodified)

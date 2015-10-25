#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Importing CPE entries in a Redis database to improve lookup
#
# Until now, this part is only used by the web interface to improve response time
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014-2015	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
import argparse
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from redis import exceptions as redisExceptions

from lib.Config import Configuration
from lib.Toolkit import pad
import lib.DatabaseLayer as db

argParser = argparse.ArgumentParser(description='CPE entries importer in Redis cache')
argParser.add_argument('-v', action='store_true', default=False, help='Verbose logging')
argParser.add_argument('-o', action='store_true', default=False, help='Import cpeother database in Redis cache')
args = argParser.parse_args()

if args.o:
    cpe = db.getAlternativeCPEs()
else:
    cpe = db.getCPEs()

try:
    r = Configuration.getRedisVendorConnection()
except:
    sys.exit(1)

for e in cpe:
    try:
        if args.o is not True:
            prefix = 'cpe_2_2'
            value = e[prefix]
        else:
            value = e['id']
        if args.o is not True:
            if e[prefix].count(':') > 4:
                value = ":".join(value.split(':')[:5])
            (prefix, cpetype, vendor, product, version) = pad(value.split(':'),5)
        else:
            (prefix, cpeversion, cpetype, vendor, product, version, *remaining) = pad(value.split(':'),6)
    except Exception as ex:
        print(ex)
        pass
    try:
        if args.v:
            print(value + " added")
        r.sadd("prefix:" + prefix, cpetype)
        r.sadd("t:" + cpetype, vendor)
        r.sadd("v:" + vendor, product)
        if version:
            r.sadd("p:" + product, version)
    except redisExceptions.ConnectionError:
        sys.exit("Redis server not running on %s:%s"%(Configuration.getRedisHost(),Configuration.getRedisPort()))

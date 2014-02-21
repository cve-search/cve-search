#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Importing CPE entries in a Redis database to improve lookup
#
# Until now, this part is only used by the web interface to improve response time
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014 Alexandre Dulaunoy - a@foo.be

import pymongo
import redis

connect = pymongo.Connection()
db = connect.cvedb
cpe = db.cpe

r = redis.StrictRedis(host='localhost', port=6379, db=10)

for e in cpe.find( {} ):
    try:
        (prefix, cpetype, vendor, product, version) = e['id'].split(':')
    except:
        pass
    r.sadd("prefix:"+prefix, cpetype)
    r.sadd("t:"+cpetype, vendor)
    r.sadd("v:"+vendor, product)
    r.sadd("p:"+product, version)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Import NIST CVE Reference Key/Maps into Redis
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015 	Alexandre Dulaunoy - a@foo.be

import os
import sys
import argparse
import re
from lxml.html import fromstring
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import zipfile
import shutil
verbose = False

from lib.Config import Configuration
import lib.DatabaseLayer as db

try:

    r = Configuration.getRedisRefConnection()
except:
    sys.exit(1)

try:
    r.info()
except:
    sys.exit("Redis server not running on %s:%s"%(Configuration.getRedisHost(),Configuration.getRedisPort()))


RefUrl = Configuration.getRefURL()
tmppath = Configuration.getTmpdir()

argparser = argparse.ArgumentParser(description='Populate/update the NIST ref database')
argparser.add_argument('-v', action='store_true', help='verbose output', default=False)
args = argparser.parse_args()

if args.v:
    verbose = True

# check modification date
try:
    u = Configuration.getFile(RefUrl)
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(RefUrl))
i = db.getLastModified('ref')
if i is not None:
    if u.headers['last-modified'] == i:
        print("Not modified")
        sys.exit(0)

# Create temp file and download and unpack database
if not os.path.exists(tmppath):
    os.mkdir(tmppath)

with open(tmppath+'/allrefmaps.zip', 'wb') as fp:
    shutil.copyfileobj(u, fp)


x = zipfile.ZipFile(tmppath+'/allrefmaps.zip')
for e in x.namelist():
    filename = e
    with x.open(filename) as infile:
        try:
            f1 = filename.split(".")[0]
            try:
                vendor = f1.split("-", 1)[1]
            except:
                continue
        except:
            continue
        htmlfile = infile.read()
        page = fromstring(htmlfile)
        rows = page.xpath("//table//tr//*")
        current = None

# Import each table into Redis
        for e in rows:
            if not e.text:
                continue
            pattern = re.compile("^"+str(vendor))
            if re.match(pattern, e.text):
                current = e.text
                continue
            element = e.text
            if not element.isspace():
                if verbose:
                    print (str(element) + "-->" + str(current))
                r.sadd(str(element), str(current))

# Data format in Redis

# SET
# CVEID -> SET of REF
# REF is VENDOR:THEIRID
# K/V
# l:VENDOR -> URL

# Update database info after successful program-run
db.setColUpdate('ref', u.headers['last-modified'])

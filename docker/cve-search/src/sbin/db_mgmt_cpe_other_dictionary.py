#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Import script of cpe (Common Platform Enumeration) definition
# into a collection used for human readable lookup of product name.
# This is locating the cpe used inside the cve, but only the cpe
# not present inside the cpe official dictionary.
#
# Exemple:
#    CVE-2014-5446 -> cpe:/a:zohocorp:manageengine_netflow_analyzer:.*
#    but 'cpe:/a:zohocorp:manageengine_netflow_analyzer' is not in the
#    cpe official dictionary.
#
# Imported in cvedb in the collection named cpeother.
#
# The format of the collection is the following
#
# { "_id" : ObjectId("50a2739eae24ac2274eae7c0"),
#     "id" : "cpe:/a:zohocorp:manageengine_netflow_analyzer:10.2",
#      "title" : "cpe:/a:zohocorp:manageengine_netflow_analyzer:10.2"
# }
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2014       psychedelys
# Copyright (c) 2014-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
import urllib

from tqdm import tqdm

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.DatabaseLayer import (
    getLastModified,
    getCVEsNewerThan,
    getCVEs,
    getAlternativeCPE,
    getCPE,
    cpeotherBulkInsert,
    setColUpdate,
)

# get dates
icve = getLastModified("cves")
icpeo = getLastModified("cpeother")

# check modification date
date = False
if icve is not None and icpeo is not None:
    # Go check date
    if icve >= icpeo:
        print("Not modified")
        sys.exit(0)
    else:
        date = True

# only get collection of new CVE's
collections = []
if date:
    collections = getCVEsNewerThan(icve)["results"]
else:
    collections = getCVEs()["results"]
# check cpes for cves and parse and store missing cpes in cpeother
batch = []

# skip on empty collections
col = list(collections)
if not col:
    print("Empty collections, import skipped")
    sys.exit(2)

for item in tqdm(col):
    for cpeentry in item["vulnerable_configuration"]:
        checkdup = getAlternativeCPE(cpeentry)
        if checkdup and len(checkdup) <= 0:
            entry = getCPE(cpeentry)
            if entry and len(entry.count) <= 0:
                title = cpeentry
                title = title[10:]
                title = title.replace(":-:", " ", 10)
                title = title.replace(":", " ", 10)
                title = title.replace("_", " ", 10)
                title = urllib.parse.unquote_plus(title)

                title = title.title()
                batch.append({"id": cpeentry, "title": title})
if len(batch) != 0:
    cpeotherBulkInsert(batch)

# update database info after successful program-run
setColUpdate("cpeother", icve)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Fulltext indexer for the MongoDB CVE collection.
#
# The fulltext indexer is relying on Whoosh.
#
# The indexing is done by enumerating all items from
# the MongoDB CVE collection and indexing the summary text of each
# CVE. The Path of each document is the CVE-ID.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2014 Alexandre Dulaunoy - a@foo.be


import pymongo
import os
import sys
import argparse

sys.path.append("./lib/")
import cves

connect = pymongo.Connection()
db = connect.cvedb
collection = db.cves

argParser = argparse.ArgumentParser(description='Fulltext indexer for the MongoDB CVE collection')
argParser.add_argument('-v', action='store_true', help='Verbose logging', default=False)
argParser.add_argument('-l', help='Number of last entries to index', default=None)
argParser.add_argument('-n', action='store_true', help='lookup complete cpe (Common Platform Enumeration) name for vulnerable configuration to add in the index', default=False)
args = argParser.parse_args()

c = cves.last(namelookup = args.n)

indexpath = "./indexdir"

from whoosh.index import create_in, exists_in, open_dir
from whoosh.fields import *

schema = Schema(title=TEXT(stored=True), path=ID(stored=True,unique=True), content=TEXT)

if not os.path.exists(indexpath):
    os.mkdir(indexpath)

if not exists_in("indexdir"):
    ix = create_in("indexdir", schema)
else:
    ix = open_dir("indexdir")

def dumpallcveid (entry=None):
    cveid = []
    if entry is None:
        for x in collection.find({}).sort('_id',1):
            cveid.append(x['id'])
    else:
        for x in collection.find({}).sort("Modified",-1).limit(int(entry)):
            cveid.append(x['id'])
    return cveid

def getcve (cveid=None):
    if cveid is None:
        return False
    return collection.find_one({'id': cveid})

for cveid in dumpallcveid(entry=args.l):
    writer = ix.writer()
    item = getcve(cveid=cveid)
    title = item['summary'][0:70]
    if args.n:
        for v in item['vulnerable_configuration']:
            cpe = c.getcpe(cpeid=v).strip('\n')
            item['summary'] += " "+cpe
    if args.v:
        print ('Indexing CVE-ID '+ str(cveid)+' '+ title)
    writer.update_document(title=title,path=cveid,content=item['summary'])
    writer.commit()

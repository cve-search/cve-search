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
# Copyright (c) 2012-2015 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 		Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import argparse

from lib.Config import Configuration
from lib.ProgressBar import progressbar
import lib.CVEs as cves
import lib.DatabaseLayer as db

argParser = argparse.ArgumentParser(description='Fulltext indexer for the MongoDB CVE collection')
argParser.add_argument('-v', action='store_true', default=False, help='Verbose logging')
argParser.add_argument('-l', default=5, help='Number of last entries to index (Default: 5) - 0 to index all documents')
argParser.add_argument('-n', action='store_true', default=False, help='lookup complete cpe (Common Platform Enumeration) name for vulnerable configuration to add in the index')
args = argParser.parse_args()

c = cves.last(namelookup=args.n)

indexpath = Configuration.getIndexdir()

from whoosh.index import create_in, exists_in, open_dir
from whoosh.fields import Schema, TEXT, ID

schema = Schema(title=TEXT(stored=True), path=ID(stored=True, unique=True), content=TEXT)

if not os.path.exists(indexpath):
    os.mkdir(indexpath)

if not exists_in(indexpath):
    ix = create_in(indexpath, schema)
else:
    ix = open_dir(indexpath)
def dumpallcveid(entry=None):
    return db.getCVEID if not entry else db.getCVEIDs(int(entry))


def getcve(cveid=None):
    if cveid is None:
        return False
    return db.getCVE(cveid)

for cveid in progressbar(dumpallcveid(entry=args.l),prefix="Processing"):
    try:
        writer = ix.writer()
    except:
        print ("Index is locked. Another db_fulltext process running?")
        sys.exit(1)
    item = getcve(cveid=cveid)
    title = item['summary'][0:70]
    if args.n:
        for v in item['vulnerable_configuration']:
            cpe = c.getcpe(cpeid=v).strip('\n')
            item['summary'] += " " + cpe
    if args.v:
        print ('Indexing CVE-ID ' + str(cveid) + ' ' + title)
    writer.update_document(title=title, path=cveid, content=item['summary'])
    writer.commit()

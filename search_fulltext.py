#!/usr/bin/env python3.1
# -*- coding: utf-8 -*-
#
# Search the CVE fulltext database
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2013 Alexandre Dulaunoy - a@foo.be

import pymongo
import os
import argparse
import sys
import json
from bson import json_util

indexpath = "./indexdir"

sys.path.append("./lib/")

from whoosh import index
from whoosh.fields import *
schema = Schema(title=TEXT(stored=True), path=ID(stored=True), content=TEXT)

ix = index.open_dir("indexdir")

from whoosh.qparser import QueryParser

argParser = argparse.ArgumentParser(description='Fulltext search for cve-search')
argParser.add_argument('-q', action='append', help='query to lookup (one or more)')
argParser.add_argument('-t', action='store_true', help='output title of the match CVE(s)')
argParser.add_argument('-f', action='store_true', help='output matching CVE(s) in JSON')
argParser.add_argument('-m', type=int, default=30, help='most frequent terms (default is 30)')
argParser.add_argument('-l', action='store_true', default=False, help='dump all terms encountered in CVE description')
argParser.add_argument('-g', action='store_true', default=False, help='graph of most frequent terms with each matching CVE (JSON output)')
argParser.add_argument('-s', action='store_true', default=False, help='enable stemming on graph JSON output (default is False)')
argParser.add_argument('-n', action='store_true', help='lookup complete cpe (Common Platform Enumeration) name for vulnerable configuration')
argParser.add_argument('-r', action='store_true', help='lookup ranking of vulnerable configuration')
args = argParser.parse_args()

if args.f or args.t:
    import cves
    cves = cves.last(rankinglookup = args.r, namelookup = args.n)

from whoosh.query import *
if args.q:
    with ix.searcher() as searcher:
        query = QueryParser("content", ix.schema).parse(" ".join(args.q))
        results = searcher.search(query, limit=None)
        for x in results:
            if not args.f:
                print (x['path'])
            else:
                print(json.dumps(cves.getcve(x['path']), sort_keys=True, default=json_util.default))
            if args.t and not args.f:
                print (" -- "+x['title'])
elif args.m and not args.l and not args.g:
    xr = ix.searcher().reader()
    for x in xr.most_frequent_terms("content", number=args.m):
        sys.stdout.write(str(int(x[0])))
        sys.stdout.write(",")
        sys.stdout.write(x[1].decode('utf-8'))
        sys.stdout.write("\n")
elif args.l and not args.g:
    xr = ix.searcher().reader()
    for x in xr.lexicon("content"):
        print (x)
elif args.g:
    import json
    if args.s:
        from nltk.stem.wordnet import WordNetLemmatizer
        from nltk.corpus import stopwords
        lmtzr = WordNetLemmatizer()
    xr = ix.searcher().reader()
    s = {"name": 'cve-search', "children": []}
    d = {}
    for x in xr.most_frequent_terms("content", 3000):
        query = QueryParser("content", ix.schema).parse(x[1])
        if args.s:
            term = lmtzr.lemmatize(x[1],'v')
            if term in stopwords.words('english'): continue
        else:
            term = x[1]
        if term in d:
            d[term]['size'] = d[term]['size']+int(x[0])
        else:
            d[term] = {}
            d[term]['size'] = int(x[0])
    for k in sorted(d.keys(), key=lambda y: (d[y]['size']), reverse=True):
        v = {}
        v["name"] = k
        v["size"] = d[k]['size']
        s['children'].append(v)
    print (json.dumps(s))
else:
    argParser.print_help()
    exit(1)

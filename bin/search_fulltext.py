#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Search the CVE full text database
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2015 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 		Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import os

from whoosh import index, qparser
from whoosh.fields import Schema, TEXT, ID
from whoosh.qparser import QueryParser

import sys
import argparse
import json
from bson import json_util

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))
from lib.Config import Configuration

indexpath = Configuration.getIndexdir()

#basepath = os.path.join(os.sep, *os.path.dirname(os.path.realpath(__file__)).rsplit('/')[:-1])
#print (os.path.split(os.path.join(basepath,indexpath)))
schema = Schema(title=TEXT(stored=True), path=ID(stored=True), content=TEXT)

ix = index.open_dir(indexpath)

argParser = argparse.ArgumentParser(description='Full text search for cve-search')
argParser.add_argument('-q', action='append', help='query to lookup (one or more)')
argParser.add_argument('-o', action='store_true', help='OR of the query to lookup (default is AND')
argParser.add_argument('-t', action='store_true', help='output title of the match CVE(s)')
argParser.add_argument('-f', action='store_true', help='output matching CVE(s) in JSON')
argParser.add_argument('-m', type=int, default=False, help='most frequent terms in CVE description (m is top-m values)')
argParser.add_argument('-l', action='store_true', default=False, help='dump all terms encountered in CVE description')
argParser.add_argument('-g', action='store_true', default=False, help='graph of most frequent terms with each matching CVE (JSON output)')
argParser.add_argument('-s', action='store_true', default=False, help='enable stemming on graph JSON output (default is False)')
argParser.add_argument('-n', action='store_true', help='lookup complete cpe (Common Platform Enumeration) name for vulnerable configuration')
argParser.add_argument('-r', action='store_true', help='lookup ranking of vulnerable configuration')
args = argParser.parse_args()

if not args.q and not args.l and not args.g and not args.m:
    argParser.print_help()
    exit(1)

if args.f or args.t:
    from lib import CVEs
    cves = CVEs.last(rankinglookup=args.r, namelookup=args.n)

if args.q:
    with ix.searcher() as searcher:
        if not args.o:
            query = QueryParser("content", ix.schema).parse(" ".join(args.q))
        else:
            query = QueryParser("content", schema=ix.schema, group=qparser.OrGroup).parse(" ".join(args.q))

        results = searcher.search(query, limit=None)
        for x in results:
            if not args.f:
                print (x['path'])
            else:
                print(json.dumps(cves.getcve(x['path']), sort_keys=True, default=json_util.default))
            if args.t and not args.f:
                print (" -- " + x['title'])
elif args.m:
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
            term = lmtzr.lemmatize(x[1].decode('utf-8'), 'v')
            if term in stopwords.words('english'):
                continue
        else:
            term = x[1]
            term = term.decode('utf-8')
        if term in d:
            d[term]['size'] = d[term]['size'] + int(x[0])
        else:
            d[term] = {}
            d[term]['size'] = int(x[0])
    for k in sorted(d.keys(), key=lambda y: (d[y]['size']), reverse=True):
        v = {}
        v["name"] = k
        v["size"] = d[k]['size']
        s['children'].append(v)
    print (json.dumps(s, indent=4))
else:
    argParser.print_help()
    exit(1)

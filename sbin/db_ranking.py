#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Import ranking values into the ranking collection.
#
# A cpe regex is use to match vulnerable configuration
# and a ranking value is assigned per a group name.
#
# The idea is to set a specific weight for a vulnerability
# when it's of a specific interest of a group/dept/organization
# within your infrastructure. This can be also used to send
# notification when you have an urgent vulnerability that need
# to be worked on.
#
# The format of the collection is the following
#
# { "_id" : ObjectId("50b1f33e597549f61b2a259b"), "cpe" : "google:chrome", "rank" : [ { "circl" : 3, "other" : 3 } ] }
# { "_id" : ObjectId("50b1fd79597549f61b2a259f"), "cpe" : "cisco", "rank" : [ { "circl" : 2 } ] }
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2012-2018  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
import argparse

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.DatabaseLayer import addRanking, findRanking, removeRanking


def add(cpe=None, key=None, rank=1):
    if cpe is None or key is None:
        return False
    return addRanking(cpe, key, rank)


def findranking(cpe=None, loosy=True):
    if cpe is None:
        return False

    result = False
    i = None

    if loosy:
        for x in cpe.split(":"):
            if x != "":
                i = findRanking(x, regex=True)
            if i is None:
                continue
            if "rank" in i:
                result = i["rank"]
    else:
        i = findRanking(cpe, regex=True)
        print(cpe)
        if i is None:
            return result
        if "rank" in i:
            result = i["rank"]

    return result


def removeranking(cpe=None):

    if cpe is None or cpe == "":
        return False

    return removeRanking(cpe)


def listranking(format="json"):
    ranks = []
    for x in findRanking():
        if format == "json":
            ranks.append(x)
        else:
            ranks.append(x["cpe"] + " " + str(x["rank"]))
    return ranks


argParser = argparse.ArgumentParser(
    description="Ranking database management for cve-search",
    epilog="You can add a specific cpe to rank: 'db_ranking.py  -c oracle:java -g mycompany -r 4'\n and then lookup "
           "for 'db_ranking.py -f java'\n Rankings encoded are used to enhance the output of the other cve-search "
           "query tools.\n",
)
argParser.add_argument("-c", type=str, help="CPE name to add (e.g. google:chrome)")
argParser.add_argument("-g", type=str, help="Name of the organization (e.g. mycompany)")
argParser.add_argument(
    "-r", type=int, default=1, help="Ranking value (integer) default value is 1"
)
argParser.add_argument("-f", type=str, help="Find ranking based on a CPE name regexp")
argParser.add_argument("-l", action="store_true", help="List all ranking")
argParser.add_argument(
    "-d", type=str, default=None, help="Remove ranking based on a CPE name regexp"
)
args = argParser.parse_args()

if args.c is not None and args.g is not None:
    add(cpe=args.c, key=args.g, rank=args.r)
elif args.f is not None:
    print(findranking(cpe=args.f))
elif args.l:
    print(listranking())
elif args.d:
    print(removeranking(cpe=args.d))
else:
    argParser.print_help()

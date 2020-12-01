#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Whitelist feature to mark CVE's for CPE's of personal interest
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2014-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
# make sure these modules are available on your system
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import argparse

from lib.cpelist import CPEList

# parse command line arguments
argparser = argparse.ArgumentParser(description='populate/update the whitelist used in webviews')
argparser.add_argument('-a', metavar="CPE", nargs="*", help='Add one or more CPE to the whitelist')
argparser.add_argument('-A', action='append', metavar="file", help='Read a file of CPEs and add them to the whitelist')
argparser.add_argument('-r', metavar="CPE", nargs="*", help='Remove one or more CPE from the whitelist')
argparser.add_argument('-R', action='append', metavar="file", help='Read a file of CPEs and remove them from the whitelist')
argparser.add_argument('-t', metavar="type", default="cpe", help='Type of item to blacklist. Default: CPE')
argparser.add_argument('-i', metavar="file", help='Import whitelist from file')
argparser.add_argument('-e', metavar="file", help='Export whitelist to file')
argparser.add_argument('-d', action='store_true', help='Drop the whitelist')
argparser.add_argument('-f', action='store_true', help='Force')
argparser.add_argument('-v', action='store_true', help='Verbose')
args = argparser.parse_args()

# Variables
collection = "whitelist"

def importWhitelist(importFile):
    oList = CPEList(collection, args)
    return oList.importList(importFile)


def exportWhitelist(exportFile=None):
    oList = CPEList(collection, args)
    return oList.exportList(exportFile)


def dropWhitelist():
    oList = CPEList(collection, args)
    return oList.dropCollection()


def countWhitelist():
    oList = CPEList(collection, args)
    return oList.countItems()


def checkWhitelist(cpe):
    oList = CPEList(collection, args)
    amount = oList.check(cpe)
    return amount


def insertWhitelist(cpe, cpeType, comments=None):
    oList = CPEList(collection, args)
    return oList.insert(cpe, cpeType, comments)


def removeWhitelist(cpe):
    oList = CPEList(collection, args)
    return oList.remove(cpe)


def updateWhitelist(cpeOld, cpeNew, cpeType):
    oList = CPEList(collection, args)
    return oList.update(cpeOld, cpeNew, cpeType)

if __name__ == '__main__':
    oList = CPEList(collection, args)
    oList.process()

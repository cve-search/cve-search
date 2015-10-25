#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Blacklist feature to mark CVE's for CPE's of personal interest
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
# make sure these modules are available on your system
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import argparse

from lib.Config import Configuration
from lib.cpelist import CPEList

# parse command line arguments
argparser = argparse.ArgumentParser(description='populate/update the blacklist used in webviews')
argparser.add_argument('-a', metavar="CPE", nargs="*", help='Add one or more CPE to the blacklist')
argparser.add_argument('-A', action='append', metavar="file", help='Read a file of CPEs and add them to the blacklist')
argparser.add_argument('-r', metavar="CPE", nargs="*", help='Remove one or more CPE from the blacklist')
argparser.add_argument('-R', action='append', metavar="file", help='Read a file of CPEs and remove them from the blacklist')
argparser.add_argument('-t', metavar="type", default="cpe", help='Type of item to blacklist. Default: CPE')
argparser.add_argument('-i', metavar="file", help='Import blacklist from file')
argparser.add_argument('-e', metavar="file", help='Export blacklist to file')
argparser.add_argument('-d', action='store_true', help='Drop the blacklist')
argparser.add_argument('-f', action='store_true', help='Force')
argparser.add_argument('-v', action='store_true', help='Verbose')
args = argparser.parse_args()

# Variables
collection = "blacklist"

# Functions
def importBlacklist(importFile):
    oList = CPEList(collection, args)
    oList.importList(importFile)


def exportBlacklist(exportFile):
    oList = CPEList(collection, args)
    oList.exportList(exportFile)


def dropBlacklist():
    oList = CPEList(collection, args)
    oList.dropCollection()


def countBlacklist():
    oList = CPEList(collection, args)
    return oList.countItems()


def checkBlacklist(cpe):
    oList = CPEList(collection, args)
    amount = oList.check(cpe)
    return amount


def insertBlacklist(cpe, cpeType):
    oList = CPEList(collection, args)
    return oList.insert(cpe,cpeType)


def removeBlacklist(cpe):
    oList = CPEList(collection, args)
    return oList.remove(cpe)


def updateBlacklist(cpeOld, cpeNew, cpeType):
    oList = CPEList(collection, args)
    return oList.update(cpeOld, cpeNew, cpeType)

if __name__ == '__main__':
    oList = CPEList(collection, args)
    oList.process()

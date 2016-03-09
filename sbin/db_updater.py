#!/usr/bin/env python3
#
#
# Updater script of CVE/CPE database
#
# Copyright (c) 2012-2016 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import shlex
import subprocess
import argparse
import time
import logging

from lib.Config import Configuration
import lib.DatabaseLayer as db

runPath = os.path.dirname(os.path.realpath(__file__))

sources = [{'name': "cves",
            'updater': "python3 " + os.path.join(runPath, "db_mgmt.py -u")},
           {'name': "cpe",
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_cpe_dictionary.py")},
           {'name': "cpeother",
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_cpe_other_dictionary.py")}]

posts = [{'name': "ensureindex",
          'updater': "python3 " + os.path.join(runPath, "db_mgmt_create_index.py")}]

argParser = argparse.ArgumentParser(description='Database updater for cve-search')
argParser.add_argument('-v', action='store_true', help='Logging on stdout')
argParser.add_argument('-l', action='store_true', help='Running at regular interval', default=False)
argParser.add_argument('-i', action='store_true', help='Indexing new cves entries in the fulltext indexer', default=False)
argParser.add_argument('-c', action='store_true', help='Enable CPE redis cache', default=False)
argParser.add_argument('-f', action='store_true', help='Drop collections and force initial import', default=False)
argParser.add_argument('-m', action='store_true', help='Minimal import', default=False)
argParser.add_argument('-o', action='store_true', help='Save log output', default=False)
argParser.add_argument('-p', action='store_true', help='Public sources only', default=False)
args = argParser.parse_args()

if not args.m:
    sources.extend([{'name': 'vfeed',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_vfeed.py")},
                    {'name': 'vendor',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_vendorstatements.py")},
                    {'name': 'cwe',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_cwe.py")},
                    {'name': 'capec',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_capec.py")},
                    {'name': 'redis-cache-cpe',
                     'updater': "python3 " + os.path.join(runPath, "db_cpe_browser.py")},
                    {'name': 'd2sec',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_d2sec.py")},
                    {'name': 'ms',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_ms.py")},
                    {'name': 'redis-nist-ref',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_ref.py")},
                    {'name': 'exploitdb',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_exploitdb.py")}])
if not args.p:
    sources.extend([{'name': 'misp',
                     'updater': "python3 " + os.path.join(runPath, "db_mgmt_misp.py")}])

if not args.v:
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
if args.f and args.l:
    print ("Drop collections and running in loop should not be used.")
    argParser.print_help()
    sys.exit(2)


def nbelement(collection=None):
    if collection is None:
        collection = "cves"
    return db.getSize(collection)

def dropcollection(collection=None):
    if collection is None:
        return False
    return db.dropCollection(collection)

def log(message=""):
    if args.o:
        with open(Configuration.getUpdateLogFile(), "a") as log:
            log .write(message + "\n")
    if args.v:
        print (message)
    else:
        logging.info(message)

loop = True

if args.f:
    log("Dropping metadata")
    dropcollection("info")

while (loop):
    if args.v:
        log("==========================")
        log(time.strftime("%a %d %B %Y %H:%M", time.gmtime()))
        log("==========================")
    if not args.l:
        loop = False
    newelement = 0
    for source in sources:
        if not Configuration.includesFeed(source['name']):
            continue
        if args.f and source['name'] is not "redis-cache-cpe":
            log("Dropping collection: " + source['name'])
            dropcollection(collection=source['name'])
            log( source['name'] + " dropped")
        if source['name'] is "cpeother":
            if "cpeother" not in db.getTableNames():
                continue
        if source['name'] is not "redis-cache-cpe":
            message = 'Starting ' + source['name']
            log(message)
            before = nbelement(collection=source['name'])
            if args.f and source['name'] is "cves":
                updater = "python3 " + os.path.join(runPath, "db_mgmt.py -p")
                subprocess.Popen((shlex.split(updater))).wait()
            else:
                subprocess.Popen((shlex.split(source['updater']))).wait()
            after = nbelement(collection=source['name'])
            message = source['name'] + " has " + str(after) + " elements (" + str(after - before) + " update)"
            newelement = str(after - before)
            log(message)
        elif (args.c is True and source['name'] is "redis-cache-cpe"):
            message = 'Starting ' + source['name']
            log(message)
            subprocess.Popen((shlex.split(source['updater']))).wait()
            message = source['name'] + " updated"
            log(message)
    for post in posts:
        message = 'Starting ' + post['name']
        log(message)
        subprocess.Popen((shlex.split(post['updater']))).wait()
    if args.i and int(newelement) > 0:
        subprocess.Popen((shlex.split("python3 " + os.path.join(runPath, "db_fulltext.py -v -l" + newelement)))).wait()
    if args.l is not False:
        log("Sleeping...")
        time.sleep(3600)
    log()

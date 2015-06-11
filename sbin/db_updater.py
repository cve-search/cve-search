#!/usr/bin/env python3
#
#
# Updater script of CVE/CPE database
#
# Copyright (c) 2012-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import shlex
import subprocess
import syslog
import argparse
import time

from lib.Config import Configuration


runPath = os.path.dirname(os.path.realpath(__file__))

sources = [{'name': "cves",
            'updater': "python3 " + os.path.join(runPath, "db_mgmt.py -u")},
           {'name': "cpe",
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_cpe_dictionary.py")},
           {'name': "cpeother",
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_cpe_other_dictionary.py")},
           {'name': 'vfeed',
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
            'updater': "python3 " + os.path.join(runPath, "db_mgmt_d2sec.py")}]
posts = [{'name': "ensureindex",
          'updater': "python3 " + os.path.join(runPath, "db_mgmt_create_index.py")}]

argParser = argparse.ArgumentParser(description='Database updater for cve-search')
argParser.add_argument('-v', action='store_true', help='Logging on stdout (default is syslog)')
argParser.add_argument('-l', action='store_true', help='Running at regular interval', default=False)
argParser.add_argument('-i', action='store_true', help='Indexing new cves entries in the fulltext indexer', default=False)
argParser.add_argument('-c', action='store_true', help='Enable CPE redis cache', default=False)
argParser.add_argument('-f', action='store_true', help='Drop collections and force initial import', default=False)
args = argParser.parse_args()

if args.f and args.l:
    print ("Drop collections and running in loop should not be used.")
    argParser.print_help()
    sys.exit(2)


def nbelement(collection=None):
    if collection is None:
        collection = "cves"
    c = Configuration.getMongoConnection()
    return c[collection].count()

def dropcollection(collection=None):
    if collection is None:
        return False
    c = Configuration.getMongoConnection()
    return c[collection].drop()

def logging(message=None):
    if args.v:
        print (message)
    else:
        syslog.syslog(message)

loop = True

if args.f:
    logging("Dropping metadata")
    dropcollection("info")

while (loop):
    if not args.l:
        loop = False
    newelement = 0
    for source in sources:
        if not Configuration.includesFeed(source['name']):
            continue
        if args.f and source['name'] is not "redis-cache-cpe":
            logging("Dropping collection: " + source['name'])
            dropcollection(collection=source['name'])
            logging( source['name'] + " dropped")
        if source['name'] is "cpeother":
            db = Configuration.getMongoConnection()
            if "cpeother" not in db.collection_names():
                continue
        if source['name'] is not "redis-cache-cpe":
            message = 'Starting ' + source['name']
            logging(message)
            before = nbelement(collection=source['name'])
            if args.f and source['name'] is "cves":
                updater = "python3 " + os.path.join(runPath, "db_mgmt.py -p")
                subprocess.Popen((shlex.split(updater))).wait()
            else:
                subprocess.Popen((shlex.split(source['updater']))).wait()
            after = nbelement(collection=source['name'])
            message = source['name'] + " has " + str(after) + " elements (" + str(after - before) + " update)"
            newelement = str(after - before)
            logging(message)
        elif (args.c is True and source['name'] is "redis-cache-cpe"):
            message = 'Starting ' + source['name']
            logging(message)
            subprocess.Popen((shlex.split(source['updater']))).wait()
            message = source['name'] + " updated"
            logging(message)
    for post in posts:
        message = 'Starting ' + post['name']
        logging(message)
        subprocess.Popen((shlex.split(post['updater']))).wait()
    if args.i and int(newelement) > 0:
        subprocess.Popen((shlex.split("python3 " + os.path.join(runPath, "db_fulltext.py -v -l" + newelement)))).wait()
    if args.l is not False:
        logging("Sleeping...")
        time.sleep(3600)

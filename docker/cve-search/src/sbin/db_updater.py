#!/usr/bin/env python3
#
# Updater script of CVE/CPE database
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2012-2019  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com
# Imports
import argparse
import logging
import os
import shlex
import subprocess
import sys
import time

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.DatabaseSchemaChecker import SchemaChecker
from lib.LogHandler import UpdateHandler
from lib.Sources_process import (
    CPEDownloads,
    CVEDownloads,
    CWEDownloads,
    CAPECDownloads,
    VIADownloads,
    CPERedisBrowser,
    DatabaseIndexer,
)
from lib.Config import Configuration
from lib.PluginManager import PluginManager
from lib.DatabaseLayer import getSize, dropCollection, getTableNames

logging.setLoggerClass(UpdateHandler)

logger = logging.getLogger("DBUpdater")

sources = [
    {"name": "cpe", "updater": CPEDownloads,},
    {"name": "cve", "updater": CVEDownloads,},
    {
        "name": "cpeother",
        "updater": "{} {}".format(
            sys.executable, os.path.join(runPath, "db_mgmt_cpe_other_dictionary.py")
        ),
    },
]

posts = [
    {"name": "ensureindex", "updater": DatabaseIndexer,},
    {"name": "schema", "updater": SchemaChecker,},
]

argParser = argparse.ArgumentParser(description="Database updater for cve-search")
argParser.add_argument("-v", action="store_true", help="Logging on stdout")
argParser.add_argument(
    "-l", action="store_true", help="Running at regular interval", default=False
)
argParser.add_argument(
    "-i",
    action="store_true",
    help="Indexing new cves entries in the fulltext indexer",
    default=False,
)
argParser.add_argument(
    "-c", action="store_true", help="Enable CPE redis cache", default=False
)
argParser.add_argument(
    "-f",
    action="store_true",
    help="Drop collections and force initial import",
    default=False,
)
argParser.add_argument("-m", action="store_true", help="Minimal import", default=False)
argParser.add_argument("-o", action="store_true", help="Save log output", default=False)
argParser.add_argument(
    "-p", action="store_true", help="Public sources only", default=False
)
args = argParser.parse_args()

if not args.m:
    sources.extend(
        [
            {"name": "cwe", "updater": CWEDownloads,},
            {"name": "capec", "updater": CAPECDownloads,},
            {"name": "redis-cache-cpe", "updater": CPERedisBrowser,},
            {"name": "via4", "updater": VIADownloads,},
        ]
    )

if not args.v:
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
if args.f and args.l:
    logger.info("Drop collections and running in loop should not be used.")
    argParser.print_help()
    sys.exit(2)


def nbelement(collection=None):
    if collection is None or collection == "cve":
        collection = "cves"
    return getSize(collection)


def dropcollection(collection=None):
    if collection is None:
        return False
    if collection == "cve":
        collection = "cves"
    ret = dropCollection(collection)
    return ret


loop = True

if args.f:
    logger.info("Dropping metadata")
    dropcollection("info")

while loop:
    if args.v:
        logger.info("==========================")
        logger.info(time.strftime("%a %d %B %Y %H:%M", time.gmtime()))
        logger.info("==========================")
    if not args.l:
        loop = False
    newelement = 0
    for source in sources:
        if (
            not Configuration.includesFeed(source["name"])
            and source["name"] != "redis-cache-cpe"
        ):
            continue
        if args.f and source["name"] != "redis-cache-cpe":
            logger.info("Dropping collection: " + source["name"])
            dropcollection(collection=source["name"])
            logger.info(source["name"] + " dropped")
        if source["name"] == "cpeother":
            if "cpeother" not in getTableNames():
                continue
        if source["name"] != "redis-cache-cpe":
            logger.info("Starting " + source["name"])
            before = nbelement(collection=source["name"])
            if args.f and source["name"] == "cpe":

                cpd = CPEDownloads()
                cpd.populate()

            elif args.f and source["name"] == "cve":

                cvd = CVEDownloads()

                cvd.populate()

            else:
                if isinstance(source["updater"], str):
                    subprocess.Popen((shlex.split(source["updater"]))).wait()
                else:
                    up = source["updater"]()
                    up.update()

            after = nbelement(collection=source["name"])
            message = (
                source["name"]
                + " has "
                + str(after)
                + " elements ("
                + str(after - before)
                + " update)"
            )
            newelement = str(after - before)
            logger.info(message)
        elif args.c is True and source["name"] == "redis-cache-cpe":
            logger.info("Starting " + source["name"])
            up = source["updater"]()
            up.update()
            logger.info(source["name"] + " updated")

    for post in posts:
        logger.info("Starting " + post["name"])
        indexer = post["updater"]()
        indexer.create_indexes()

    if args.i and int(newelement) > 0:
        subprocess.Popen(
            (
                shlex.split(
                    "{} {} {}".format(
                        sys.executable,
                        os.path.join(runPath, "db_fulltext.py"),
                        "-v -l " + newelement,
                    )
                )
            )
        ).wait()
    if args.l is not False:
        logger.info("Sleeping...")
        time.sleep(3600)

if not args.p:
    plugManager = PluginManager()
    plugManager.loadPlugins()
    plugins = plugManager.getPlugins()
    if len(plugins) != 0:
        for plug in plugins:
            logger.info("Starting " + plug.getName() + " plugin")
            message = plug.onDatabaseUpdate()
            if message:
                logger.info(message)

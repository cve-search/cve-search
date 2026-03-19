#!/usr/bin/env python3
#
# Updater script of CVE/CPE database
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2012-2019  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import argparse
import logging
import os
import shlex
import subprocess
import sys
import time

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))


from lib.Config import Configuration

# pass configuration to CveXplore
Configuration.setCveXploreEnv()
from CveXplore import CveXplore

from lib.LogHandler import UpdateHandler
from lib.Sources_process import (
    CPERedisBrowser,
)
from lib.DatabaseLayer import (
    getSize,
    dropCollection,
    getTableNames,
    acquire_lock,
    release_lock,
    any_lock_active,
)

logging.setLoggerClass(UpdateHandler)

logger = logging.getLogger("DBUpdater")


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


def _acquire_all_locks_or_none(sources):
    """
    Attempt to acquire locks for all sources.

    Returns:
        tuple(list_of_locked_names, failed_source_name):
            - list_of_locked_names: names of sources successfully locked
            - failed_source_name: name of the first source that could not be locked (None if all succeeded)
    """
    acquired = []
    for name in sources:
        if acquire_lock(name):
            acquired.append(name)
        else:
            # Release any locks we already acquired
            for s in acquired:
                release_lock(s)
            return None, name  # indicate which source caused failure
    return acquired, None


def main(args):
    cvex = CveXplore()

    # Repopulation

    if args.force:
        logger.info("==========================")
        logger.info("Repopulate")
        logger.info(time.strftime("%a %d %B %Y %H:%M", time.gmtime()))
        logger.info("==========================")

        repopulate_wait_max = 8
        repopulate_wait_interval = 300  # seconds
        for attempt in range(1, repopulate_wait_max + 1):
            if any_lock_active():
                logger.warning(
                    "Active updater locks detected. "
                    f"Waiting {repopulate_wait_interval} seconds for other db_updater processes to finish "
                    f"(Try {attempt}/{repopulate_wait_max})"
                )
                time.sleep(repopulate_wait_interval)
            else:
                break
        else:  # executes only if the loop did not break
            logger.error(
                "Active updater locks still detected after maximum wait. Aborting database repopulation."
            )
            sys.exit(1)

        # Lock all available CveXplore sources for the repopulation
        available_sources = []
        for source_available in cvex.database.sources:
            available_sources.append(source_available["name"])
        locked_sources, failed_source = _acquire_all_locks_or_none(available_sources)
        if not locked_sources:
            logger.error(f"Failed to lock {failed_source} for repopulation. Aborting.")
            sys.exit(1)
        try:
            to_drop = ["cpeother", "info", "schema"]
            for each in to_drop:
                logger.info(f"Dropping metadata: {each}")
                dropcollection(each)
            if args.loop and args.days == 0:
                logger.info(
                    "Drop collections (-f, --force) and running in loop (-l, --loop) used together; only dropping on the first iteration."
                )

            logger.info("Starting initial import...")
            cvex.database.initialize()
        finally:
            for name in locked_sources:
                release_lock(name)

    # Get sources from arguments or configuration and compare with sources provided by CveXplore

    update_sources = []
    ignored_sources = []
    if len(args.sources) > 0:
        logger.info(
            f'Using manually overridden sources instead of configured: {", ".join(args.sources)}'
        )
    for source_available in cvex.database.sources:
        if source_available["name"] in args.sources:
            update_sources.append(source_available["name"])
        elif len(args.sources) == 0 and Configuration.includesFeed(
            source_available["name"]
        ):
            update_sources.append(source_available["name"])
        else:
            ignored_sources.append(source_available["name"])
    if len(ignored_sources) > 0:
        logger.info(
            f'Ignored available CveXplore sources: {", ".join(ignored_sources)}'
        )
    if len(args.sources) > 0:
        unavailable_sources = [i for i in args.sources if i not in update_sources]
        if len(unavailable_sources) > 0:
            logger.warning(
                f'Sources unavailable in CveXplore: {", ".join(unavailable_sources)}'
            )
    if len(update_sources) == 0:
        logger.error(f"None of the sources available in CveXplore.")
        return 1

    # Update sources handled by CveXplore

    loop = True
    loop_count = 0

    while loop:
        if args.loop and args.days > 0:
            logger.warning(
                f"Loop (-l, --loop) not supported with manual days (-d, --days); only running once"
            )
        if not args.loop or args.days > 0:
            loop = False
        else:
            loop_count += 1

        logger.info("==========================")
        if args.cache:
            redis_info = " ; CPE redis cache enabled"
        else:
            redis_info = ""
        if args.days > 0:
            days_info = f" (manual interval of {str(args.days)} days)"
            loop_info = ""  # loop not supported with manual days
        else:
            days_info = ""
            if args.loop:
                loop_info = f" (loop #{loop_count})"
            else:
                loop_info = ""
        logger.info(
            f'Update [{", ".join(update_sources)}]{redis_info}{loop_info}{days_info}'
        )
        logger.info(time.strftime("%a %d %B %Y %H:%M", time.gmtime()))
        logger.info("==========================")

        locked_sources, failed_source = _acquire_all_locks_or_none(update_sources)
        if not locked_sources:
            if failed_source:
                if len(update_sources) == 1:
                    logger.warning(
                        f"Source {failed_source} is already locked; skipping CveXplore update"
                    )
                else:
                    logger.warning(
                        f"Could not acquire lock for source {failed_source}; skipping CveXplore batch update"
                    )
            else:
                logger.info(f"Nothing to update with CveXplore.")
        else:
            try:
                cvex.database.update(
                    update_source=update_sources, manual_days=args.days
                )
            finally:
                for name in locked_sources:
                    release_lock(name)

        # Update sources other than CveXplore

        sources = []
        if Configuration.includesFeed("cpeother"):
            sources.extend(
                [
                    {
                        "name": "cpeother",
                        "updater": "{} {}".format(
                            sys.executable,
                            os.path.join(runPath, "db_mgmt_cpe_other_dictionary.py"),
                        ),
                    }
                ]
            )
        if args.cache:
            sources.extend(
                [
                    {"name": "redis-cache-cpe", "updater": CPERedisBrowser},
                ]
            )

        for source in sources:
            if not acquire_lock(source["name"]):
                logger.warning(
                    f"Source {source['name']} is already locked by another update, skipping update"
                )
                continue
            try:
                # Drop collections only if this was the first iteration of a repopulation
                if (
                    args.force
                    and source["name"] != "redis-cache-cpe"
                    and loop_count < 2
                ):
                    logger.info("Repopulation; dropping collection: " + source["name"])
                    if dropcollection(collection=source["name"]):
                        logger.info(f"{source['name']} dropped")
                    else:
                        logger.info(f"{source['name']} did not exist")

                if (
                    not Configuration.includesFeed(source["name"])
                    and source["name"] != "redis-cache-cpe"
                ):
                    logger.info(f"Skipping non-configured source: {source['name']}")
                    continue

                if source["name"] == "cpeother":
                    if "cpeother" not in getTableNames():
                        continue
                if source["name"] != "redis-cache-cpe":
                    logger.info("Starting " + source["name"])
                    before = nbelement(collection=source["name"])

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
                    logger.info(message)
                elif args.cache is True and source["name"] == "redis-cache-cpe":
                    logger.info("Starting " + source["name"])
                    up = source["updater"]()
                    up.update()
                    logger.info(source["name"] + " updated")
            finally:
                release_lock(source["name"])

        if args.index:
            logger.warning(
                "Fulltext indexing has been removed from db_updater.py. "
                "Use db_fulltext.py to manage fulltext index."
            )

        if args.loop and args.days == 0:
            logger.info("Sleeping 1 hour...")
            time.sleep(3600)


if __name__ == "__main__":
    argParser = argparse.ArgumentParser(description="Database updater for cve-search")
    argParser.add_argument(
        "-s",
        "--sources",
        nargs="*",
        metavar="SOURCE",
        help="Sources to be updated if available in CveXplore. Defaults to all sources available & configured.",
        default=[],
    )
    argParser.add_argument(
        "-i",
        "--index",
        action="store_true",
        help=(
            "Dummy option for backwards compatibility. ",
            "Use sbin/db_fulltext.py for indexing CVE entries in the fulltext indexer",
        ),
        default=False,
    )
    argParser.add_argument(
        "-l",
        "--loop",
        action="store_true",
        help="Running at regular interval; waits 1 hour (disabled with -d, --days)",
        default=False,
    )
    argParser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Drop collections and force initial import (only on first iteration with -l, --loop)",
        default=False,
    )
    argParser.add_argument(
        "-d",
        "--days",
        type=int,
        choices=range(1, 121),
        metavar="1..120",
        help="Set update interval (1-120 days) manually for NVD API (CPE, CVE)",
        default=0,  # not manually set; updates CPE & CVE since last update
    )
    argParser.add_argument(
        "-c",
        "--cache",
        action="store_true",
        help="Enable CPE redis cache",
        default=False,
    )
    args = argParser.parse_args()

    main(args)

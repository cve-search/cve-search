#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Script to check and ensure that the recommended indexes are created.
#
# NOTE: Legacy tool. Indexes are created automatically during database
# updates, so running this script is generally unnecessary. Can still
# be used to refresh indexes without performing a full update.
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2014       psychedelys
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com
# Imports
import logging
import os
import sys

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.Config import Configuration
from CveXplore.core.database_indexer.db_indexer import DatabaseIndexer
from lib.LogHandler import UpdateHandler

logging.setLoggerClass(UpdateHandler)

# pass configuration to CveXplore
Configuration.setCveXploreEnv()


class DatabaseWrapper:
    """
    Adapt a raw pymongo Database object for CveXplore's DatabaseIndexer that
    expect a '.dbclient' attribute exposing the underlying MongoDB database.
    Unfortunately, the 'Configuration.getMongoConnection()' already returns a
    'pymongo.database.Database' instance, which does not define '.dbclient'.
    This wrapper resolves that mismatch.
    """

    def __init__(self, db):
        self.dbclient = db


if __name__ == "__main__":
    db = Configuration.getMongoConnection()
    di = DatabaseIndexer(DatabaseWrapper(db))
    di.create_indexes()

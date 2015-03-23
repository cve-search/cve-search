#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Script to check and ensure that the recommended index are created as recommended.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014 	psychedelys
# Copyright (c) 2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import traceback

from lib.Config import Configuration

db = Configuration.getMongoConnection()


def setIndex(col, field):
    try:
        collection = db[col]
        collection.ensure_index(field)
        print('[+]Success to create index %s on %s' % (field, col))
    except Exception:
        print('[-]Failed to create index %s on %s' % (collection, field))
        traceback.print_exc()
        print('=======')
        pass

setIndex('cpe', 'id')
setIndex('cpeother', 'id')
setIndex('cves', 'id')
setIndex('cves', 'vulnerable_configuration')
setIndex('cves', 'Modified')
setIndex('vfeed', 'id')
setIndex('vendor', 'id')
setIndex('d2sec', 'id')
setIndex('mgmt_whitelist', 'id')
setIndex('mgmt_blacklist', 'id')
setIndex('capec', 'related_weakness')

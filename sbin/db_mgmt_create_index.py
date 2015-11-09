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

from pymongo import TEXT

from lib.Config import Configuration
import lib.DatabaseLayer as dbLayer

def setIndex(col, field):
    try:
        dbLayer.ensureIndex(col, field)
        print('[+]Success to create index %s on %s' % (field, col))
    except Exception as e:
        print('[-]Failed to create index %s on %s: %s' % (col, field, e))

setIndex('cpe', 'id')
setIndex('cpeother', 'id')
setIndex('cves', 'id')
setIndex('cves', 'vulnerable_configuration')
setIndex('cves', 'Modified')
setIndex('cves', [("summary",TEXT)])
setIndex('vfeed', 'id')
setIndex('vendor', 'id')
setIndex('d2sec', 'id')
setIndex('mgmt_whitelist', 'id')
setIndex('mgmt_blacklist', 'id')
setIndex('capec', 'related_weakness')
setIndex('exploitdb', 'id')

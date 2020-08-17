#!/usr/bin/env python3
#
# Import script of CAPEC references.
#
# Imported in cvedb in the collection named capec.
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2016-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.Sources_process import CAPECDownloads

if __name__ == "__main__":
    cad = CAPECDownloads()

    lastmodified = cad.populate()

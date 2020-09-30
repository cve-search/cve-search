#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Import script of NIST CWE Common Weakness Enumeration.
#
# Until now, the import is only import Weakness description.
#
# The format is the following:
#
# { "_id" : ObjectId("52b70521b261026f36818515"), "weaknessabs" : "Variant",
# "name" : "ASP.NET Misconfiguration: Missing Custom Error Page",
# "description_summary" : "An ASP .NET application must enable custom error
# pages in order to prevent attackers from mining information from the
# framework's built-in responses.An ASP .NET application must enable custom
# error pages in order to prevent attackers from mining information from the
# framework's built-in responses.", "status" : "Draft", "id" : "12" }
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2013-2018  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import argparse
import os
import sys

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.Sources_process import CWEDownloads

argparser = argparse.ArgumentParser(
    description="populate/update NIST CWE Common Weakness Enumeration database"
)
argparser.add_argument("-v", action="store_true", help="verbose output")
argparser.add_argument("-f", action="store_true", help="force update")
args = argparser.parse_args()


if __name__ == "__main__":
    cwd = CWEDownloads()

    lastmodified = cwd.populate()

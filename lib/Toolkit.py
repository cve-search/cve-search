#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Toolkit for functions between scripts
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2014-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import re

import lib.cpe_conversion


# Note of warning: CPEs like cpe:/o:microsoft:windows_8:-:-:x64 are given to us by Mitre
#  x64 will be parsed as Edition in this case, not Architecture
def toStringFormattedCPE(cpe, autofill=False):
    cpe = cpe.strip()
    if not cpe.startswith("cpe:2.3:"):
        if not cpe.startswith("cpe:/"):
            return False
        cpe = lib.cpe_conversion.cpe_uri_to_fs(cpe)
    if autofill:
        e = lib.cpe_conversion.split_cpe_name(cpe)
        for x in range(0, 13 - len(e)):
            cpe += ":-"
    return cpe


# Note of warning: Old CPE's can come in different formats, and are not uniform. Possibilities are:
# cpe:/a:7-zip:7-zip:4.65::~~~~x64~
# cpe:/a:7-zip:7-zip:4.65:-:~~~~x64~
# cpe:/a:7-zip:7-zip:4.65:-:~-~-~-~x64~
def toOldCPE(cpe):
    cpe = cpe.strip()
    if not cpe.startswith("cpe:/"):
        if not cpe.startswith("cpe:2.3:"):
            return False
        cpe = lib.cpe_conversion.cpe_fs_to_uri(cpe)
    return cpe


def isURL(string):
    urlTypes = [re.escape(x) for x in ["http://", "https://", "www."]]
    return re.match("^(" + "|".join(urlTypes) + ")", string)


def tk_compile(regexes):
    if type(regexes) not in [list, tuple]:
        regexes = [regexes]
    r = []
    for rule in regexes:
        r.append(re.compile(rule))
    return r

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Toolkit for functions between scripts
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2014-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import re

import dateutil.parser
from dateutil import tz


# Note of warning: CPEs like cpe:/o:microsoft:windows_8:-:-:x64 are given to us by Mitre
#  x64 will be parsed as Edition in this case, not Architecture
def toStringFormattedCPE(cpe, autofill=False):
    cpe = cpe.strip()
    if not cpe.startswith("cpe:2.3:"):
        if not cpe.startswith("cpe:/"):
            return False
        cpe = cpe.replace("cpe:/", "cpe:2.3:")
        cpe = cpe.replace("::", ":-:")
        cpe = cpe.replace("~-", "~")
        cpe = cpe.replace("~", ":-:")
        cpe = cpe.replace("::", ":")
        cpe = cpe.strip(":-")
        cpe = unquote(cpe)
    if autofill:
        e = cpe.split(":")
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
        cpe = cpe.replace("cpe:2.3:", "")
        parts = cpe.split(":")
        next = []
        first = "cpe:/" + ":".join(parts[:5])
        last = parts[5:]
        if last:
            for x in last:
                next.append("~") if x == "-" else next.append(x)
            if "~" in next:
                pad(next, 6, "~")
        cpe = "%s:%s" % (first, "".join(next))
        cpe = cpe.replace(":-:", "::")
        cpe = cpe.strip(":")
    return cpe


def pad(seq, target_length, padding=None):
    length = len(seq)
    if length > target_length:
        return seq
    seq.extend([padding] * (target_length - length))
    return seq


def currentTime(utc):
    timezone = tz.tzlocal()
    utc = dateutil.parser.parse(utc)
    output = utc.astimezone(timezone)
    output = output.strftime("%d-%m-%Y - %H:%M")
    return output


def isURL(string):
    urlTypes = [re.escape(x) for x in ["http://", "https://", "www."]]
    return re.match("^(" + "|".join(urlTypes) + ")", string)


def vFeedName(string):
    string = string.replace("map_", "")
    string = string.replace("cve_", "")
    return string.title()


def mergeSearchResults(database, plugins):
    if "errors" in database:
        results = {"data": [], "errors": database["errors"]}
    else:
        results = {"data": []}

    data = []
    data.extend(database["data"])
    data.extend(plugins["data"])
    for cve in data:
        if not any(cve["id"] == entry["id"] for entry in results["data"]):
            results["data"].append(cve)
    return results


def tk_compile(regexes):
    if type(regexes) not in [list, tuple]:
        regexes = [regexes]
    r = []
    for rule in regexes:
        r.append(re.compile(rule))
    return r


# Convert cpe2.2 url encoded to cpe2.3 char escaped
# cpe:2.3:o:cisco:ios:12.2%281%29 to cpe:2.3:o:cisco:ios:12.2\(1\)
def unquote(cpe):
    return re.compile("%([0-9a-fA-F]{2})", re.M).sub(
        lambda m: "\\" + chr(int(m.group(1), 16)), cpe
    )


# Generates a human readable title from a CPE 2.3 string
def generate_title(cpe):
    title = ""

    cpe_split = cpe.split(":")
    # Do a very basic test to see if the CPE is valid
    if len(cpe_split) == 13:

        # Combine vendor, product and version
        title = " ".join(cpe_split[3:6])

        # If "other" is specified, add it to the title
        if cpe_split[12] != "*":
            title += cpe_split[12]

        # Capitilize each word
        title = title.title()

        # If the target_sw is defined, add "for <target_sw>" to title
        if cpe_split[10] != "*":
            title += " for " + cpe_split[10]

        # In CPE 2.3 spaces are replaced with underscores. Undo it
        title = title.replace("_", " ")

        # Special characters are escaped with \. Undo it
        title = title.replace("\\", "")

    return title

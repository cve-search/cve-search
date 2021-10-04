#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Lookup NIST CVE Reference Key/Maps from a CVE
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2015-2018  Alexandre Dulaunoy - a@foo.be


import os
import sys
import argparse
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))


from lib.Config import Configuration

try:

    r = Configuration.getRedisRefConnection()
except:
    sys.exit(1)

argparser = argparse.ArgumentParser(description='Lookup the NIST ref database')
argparser.add_argument('-c', help='CVE id to lookup', default=False)
argparser.add_argument('-u', action='store_true', help='Enable URL expansion', default=False)
argparser.add_argument('-v', action='store_true', help='verbose output', default=False)
args = argparser.parse_args()

if not args.c:
    sys.exit("CVE id missing")

ref_urls = {"MS": "https://technet.microsoft.com/library/security/",
            "SECUNIA": "http://secunia.com/advisories/",
            "SREASON": "http://securityreason.com/security_alert",
            "CERT": "http://www.cert.org/advisories",
            "BID": "http://www.securityfocus.com/bid/",
            "AIXAPART": "",
            "ALLAIRE": "",
            "APPLE": "",
            "ASCEND": "",
            "ATSTAKE": "",
            "AUSCERT": "",
            "BEA": "",
            "BINDVIEW": "",
            "SECTRACK": "http://www.securitytracker.com/id/",
            "MANDRIVA": "http://www.mandriva.com/security/advisories?name="}

refs = r.smembers(args.c)

if not refs:
    sys.exit("{} has no NIST references".format(args.c))

for ref in refs:
    if args.u:
        (provider, refid) = ref.split(":", 1)
        if provider in ref_urls.keys():
            print ("{}{}".format(ref_urls[provider], refid))
        elif provider == 'CONFIRM':
            print ("{}".format(refid))
        else:
            print (ref)
    else:
        print (ref)

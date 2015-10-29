#!/usr/bin/env python3
#
# Import script of NIST nvd vendor statement.
#
# Imported in cvedb in the collection named vendor.
#
# The format of the collection is the following:
# { "_id" : ObjectId("52b5b33ab261021ad289f3ee"), "lastmodified" : "2006-09-27T00:00:00.000-04:00", "statement" : "CVE-2001-0935 refers to vulnerabilities found when SUSE did a code audit of the wu-ftpd glob.c file in wu-ftpd 2.6.0. They shared these details with the wu-ftpd upstream authors who clarified that some of the issues did not apply, and all were addressed by the version of glob.c in upstream wu-ftpd 2.6.1. Therefore we believe that the issues labelled as CVE-2001-0935 do not affect wu-ftpd 2.6.1 or later versions and therefore do not affect Red Hat Enterprise Linux 2.1.CVE-2001-0935 refers to vulnerabilities found when SUSE did a code audit of the wu-ftpd glob.c file in wu-ftpd 2.6.0. They shared these details with the wu-ftpd upstream authors who clarified that some of the issues did not apply, and all were addressed by the version of glob.c in upstream wu-ftpd 2.6.1. Therefore we believe that the issues labelled as CVE-2001-0935 do not affect wu-ftpd 2.6.1 or later versions and therefore do not affect Red Hat Enterprise Linux 2.1.", "contributor" : "Joshua Bressers", "organization" : "Red Hat", "id" : "CVE-2001-0935" }
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2013 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import argparse

from lib.ProgressBar import progressbar
from lib.Config import Configuration

import lib.DatabaseLayer as db

argparser = argparse.ArgumentParser(description='populate/update vendor statement database')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()


class VendorHandler(ContentHandler):
    def __init__(self):
        self.vendor = []
        self.statementtag = False

    def startElement(self, name, attrs):
        if name == 'nvd:statement':
            self.statement = ""
            self.organization = attrs.get('organization')
            self.lastmodified = attrs.get('lastmodified')
            self.cvename = attrs.get('cvename')
            self.contributor = attrs.get('contributor')
            self.vendor.append({'organization': self.organization, 'lastmodified': self.lastmodified, 'id': self.cvename, 'contributor': self.contributor, 'statement': self.statement})
            self.statementtag = True

    def characters(self, ch):
        if self.statementtag:
            self.statement += ch

    def endElement(self, name):
        if name == 'nvd:statement':
            self.statementtag = False
            self.statement = self.statement + self.statement.rstrip()
            self.vendor[-1]['statement'] = self.statement

# dictionary
vendordict = Configuration.getVendorDict()

# make parser
parser = make_parser()
ch = VendorHandler()
parser.setContentHandler(ch)
# check modification date
try:
    (f, r) = Configuration.getFile(vendordict, compressed = True)
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(vendordict))
i = db.getLastModified('vendor')
if i is not None:
    if r.headers['last-modified'] == i:
        print("Not modified")
        sys.exit(0)
# parse xml and store in database
parser.parse(f)
statements=[]
for statement in progressbar(ch.vendor):
    if args.v:
        print (statement)
    statements.append(statement)
db.bulkUpdate('vendor', statements)

#update database info after successful program-run
db.setColUpdate('vendor', r.headers['last-modified'])

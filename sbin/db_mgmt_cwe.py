#!/usr/bin/env python3
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
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2013-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 		Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import argparse
import zipfile
import tempfile

from lib.ProgressBar import progressbar
from lib.Config import Configuration
import lib.DatabaseLayer as db

argparser = argparse.ArgumentParser(description='populate/update NIST CWE Common Weakness Enumeration database')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()

class CWEHandler(ContentHandler):
    def __init__(self):
        self.cwe = []
        self.description_summary_tag = False
        self.weakness_tag = False

    def startElement(self, name, attrs):
        if name == 'Weakness':
            self.weakness_tag = True
            self.statement = ""
            self.weaknessabs = attrs.get('Weakness_Abstraction')
            self.name = attrs.get('Name')
            self.idname = attrs.get('ID')
            self.status = attrs.get('Status')
            self.cwe.append({'name': self.name, 'id': self.idname, 'status': self.status, 'weaknessabs': self.weaknessabs})
        elif name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = True
            self.description_summary = ""

    def characters(self, ch):
        if self.description_summary_tag:
            self.description_summary += ch.replace("       ", "")

    def endElement(self, name):
        if name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = False
            self.description_summary = self.description_summary + self.description_summary
            self.cwe[-1]['description_summary'] = self.description_summary.replace("\n", "")
        elif name == 'Weakness':
            self.weakness_tag = False

# dictionary
cwedict = Configuration.getCWEDict()

# make parser
parser = make_parser()
ch = CWEHandler()
parser.setContentHandler(ch)
# check modification date
try:
    f = Configuration.getFile(cwedict)
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(cwedict))
lastmodified = f.headers['last-modified']
i = db.getLastModified('cwe')
if i is not None:
    if lastmodified == i:
        print("Not modified")
        sys.exit(0)

# preparing xml by saving in a tempfile and unzipping
tmpdir = tempfile.gettempdir()
tmpfile = tempfile.NamedTemporaryFile()
cwezip = open(tmpfile.name, 'wb')
cwezip.write(f.read())
cwezip.close()
with zipfile.ZipFile(tmpfile.name) as z:
    z.extractall(tmpdir)
    z.close()
f = open(os.path.join(tmpdir, 'cwec_v2.8.xml'))
# parse xml and store in database
parser.parse(f)
cweList=[]
for cwe in progressbar(ch.cwe):
    cwe['description_summary']=cwe['description_summary'].replace("\t\t\t\t\t", " ")
    if args.v:
        print (cwe)
    cweList.append(cwe)
db.bulkUpdate('cwe', cweList)

#update database info after successful program-run
db.setColUpdate('cwe', lastmodified)

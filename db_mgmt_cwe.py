#!/usr/local/bin/python3
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
# Copyright (c) 2013 Alexandre Dulaunoy - a@foo.be


from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from urllib.request import urlopen
import argparse
import pymongo
import sys
import zipfile
import tempfile
import os
cwedict = "http://cwe.mitre.org/data/xml/cwec_v2.5.xml.zip"

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
            self.description_summary += ch.replace("       ","")

    def endElement(self, name):
        if name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = False
            self.description_summary = self.description_summary + self.description_summary
            self.cwe[-1]['description_summary'] = self.description_summary.replace("\n","")
        elif name == 'Weakness':
            self.weakness_tag = False


#MongoDB
connect = pymongo.Connection()
db = connect.cvedb
cwedb = db.cwe
info = db.info


parser = make_parser()
ch = CWEHandler()
parser.setContentHandler(ch)
f = urlopen(cwedict)
i = info.find_one({'db': 'cwe'})
if i is not None:
    if f.headers['last-modified'] == i['last-modified']:
        sys.exit("Not modified")
info.update({'db': 'cwe'}, {"$set":{'last-modified': f.headers['last-modified']}}, upsert=True)

tmpdir = tempfile.gettempdir()
tmpfile = tempfile.NamedTemporaryFile()
cwezip = open(tmpfile.name, 'wb')
cwezip.write(f.read())
cwezip.close()
with zipfile.ZipFile(tmpfile.name) as z:
    z.extractall(tmpdir)

f = open(os.path.join(tmpdir, 'cwec_v2.5.xml'))

parser.parse(f)

for cwe in ch.cwe:
    if args.v:
        print (cwe)
    entry = cwedb.find({'id': cwe['id']})
    if entry.count() > 0:
        cwedb.update({'id': cwe['id']}, {"$set":{'name': cwe['name'], 'id': cwe['id'], 'status': cwe['status'], 'weaknessabs': cwe['weaknessabs']}})
    else:
        cwedb.insert(cwe)

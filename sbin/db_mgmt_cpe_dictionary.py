#!/usr/bin/env python3
#
# Import script of nvd cpe (Common Platform Enumeration) definition
# into a collection used for human readable lookup of product name.
#
# Imported in cvedb in the collection named cpe.
#
# The format of the collection is the following
#
# { "_id" : ObjectId("50a2739eae24ac2274eae7c0"), "id" :
# "cpe:/a:1024cms:1024_cms:0.7", "title" : "1024cms.org 1024 CMS 0.7" }
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012 		Wim Remes
# Copyright (c) 2012-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from xml.sax import make_parser
from xml.sax.handler import ContentHandler

from lib.ProgressBar import progressbar
from lib.Toolkit import toStringFormattedCPE
from lib.Config import Configuration
import lib.DatabaseLayer as db

class CPEHandler(ContentHandler):
    def __init__(self):
        self.cpe = []
        self.titletag = False
        self.referencestag = False
        self.referencetag = False

    def startElement(self, name, attrs):
        if name == 'cpe-item':
            self.name = ""
            self.title = ""
            self.referencetitle = ""
            self.name = attrs.get('name')
            self.cpe.append({'name': attrs.get('name'), 'title': [], 'references': []})
        elif name == 'title':
            if attrs.get('xml:lang') == 'en-US':
                self.titletag = True
        elif name == 'references':
            self.referencestag = True
        elif name == 'reference':
            self.referencetag = True
            self.href = attrs.get('href')
            self.cpe[-1]['references'].append(self.href)

    def characters(self, ch):
        if self.titletag:
            self.title += ch

    def endElement(self, name):
        if name == 'cpe-item':
            self.titletag = False
            self.cpe[-1]['title'].append(self.title.rstrip())
        elif name == 'references':
            self.referencestag = False
        elif name == 'reference':
            self.referencetag = False
            self.href = None

# dict
cpedict = Configuration.getCPEDict()

# make parser
parser = make_parser()
ch = CPEHandler()
parser.setContentHandler(ch)
# check modification date
try:
    f = Configuration.getFile(cpedict)
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(cpedict))
i = db.getLastModified('cpe')
if i is not None:
    if f.headers['last-modified'] == i:
        print("Not modified")
        sys.exit(0)
# parse xml and store in database
parser.parse(f)
cpeList=[]
for x in progressbar(ch.cpe):
  x['id']= toStringFormattedCPE(x['name'])
  x['title']=x['title'][0]
  x['cpe_2_2'] = x.pop('name')
  if not x['references']: x.pop('references')
  cpeList.append(x)
db.bulkUpdate("cpe", cpeList)

#update database info after successful program-run
db.setColUpdate('cpe', f.headers['last-modified'])

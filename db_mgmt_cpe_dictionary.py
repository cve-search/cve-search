#!/usr/local/bin/python3
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
# Copyright (c) 2012 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2012 Wim Remes


from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from urllib.request import urlopen
import pymongo
import sys
cpedict = "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml"


class CPEHandler(ContentHandler):
    def __init__(self):
        self.cpe = []
        self.titletag = False

    def startElement(self, name, attrs):
        if name == 'cpe-item':
            self.name = ""
            self.title= ""
            self.name = attrs.get('name')
            self.cpe.append({'name': attrs.get('name'),'title': []})
        elif name == 'title':
            if attrs.get('xml:lang') == 'en-US':
                self.titletag = True

    def characters(self, ch):
        if self.titletag:
            self.title += ch

    def endElement(self, name):
        if name == 'cpe-item':
            self.titletag = False
            self.cpe[-1]['title'].append(self.title.rstrip())


#MongoDB
connect = pymongo.Connection()
db = connect.cvedb
cpe = db.cpe
info = db.info


parser = make_parser()
ch = CPEHandler()
parser.setContentHandler(ch)
f = urlopen(cpedict)
i = info.find_one({'db': 'cpe'})
if i is not None:
    if f.headers['last-modified'] == i['last-modified']:
        sys.exit("Not modified")
parser.parse(f)
info.update({'db': 'cpe'}, {"$set":{'last-modified': f.headers['last-modified']}}, upsert=True)

for x in ch.cpe:
     name = x['name']
     title = x['title'][0]
     cpeelement = {'id': name,'title': title}
     entry = cpe.find(({'id': name}))
     if entry.count() > 0:
        cpe.update({'id': name}, {"$set":{'title': title}})
     else:
        cpe.insert(cpeelement)

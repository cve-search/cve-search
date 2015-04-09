#!/usr/bin/env python3
#
# Import script of D2sec references.
#
# Imported in cvedb in the collection named d2sec.
#
# Copyright (c) 2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from urllib.request import urlopen
import argparse

from lib.ProgressBar import progressbar
from lib.Config import Configuration

argparser = argparse.ArgumentParser(description='populate/update d2sec exploit database')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()


class ExploitHandler(ContentHandler):
    def __init__(self):
        self.d2sec = []
        self.exploittag = False
        self.elliottag = False
        self.nametag = False
        self.urltag = False
        self.reltag = False
        self.refcvetag = False
        self.tag = False
        self.refl = []

    def startElement(self, name, attrs):
        if name == 'elliot':
            self.elliottag = True
        if name == 'exploit' and self.elliottag:
            self.exploittag = True

        if self.exploittag:
            self.tag = name
            if self.tag == 'name':
                self.nametag = True
                self.name = ""
            elif self.tag == 'url':
                self.urltag = True
                self.url = ""
            elif self.tag == 'ref':
                self.reftag = True
                self.reftype = attrs.getValue('type')
                if self.reftype == 'CVE':
                    self.refcvetag = True
                    self.cveref = ""
                elif self.reftype != 'CVE':
                    self.refcvetag = False

    def characters(self, ch):
        if self.nametag:
            self.name += ch
        elif self.urltag:
            self.url += ch
        elif self.refcvetag:
            self.cveref += ch

    def endElement(self, name):
        if name == 'ref':
            if self.cveref != "":
                self.refl.append(self.cveref.rstrip())
            self.reftag = False
        if name == 'name':
            self.nametag = False
        if name == 'url':
            self.urltag = False
        if name == 'ref':
            self.reftag = False
        if name == 'exploit':
            for refl in self.refl:
                self.d2sec.append({'name': self.name, 'url': self.url, 'id': refl})
            self.exploittag = False
            self.refl = []
        if name == 'elliot':
            self.elliottag = False

# dictionary
d2securl = Configuration.getd2secDict()

# connect to db
db = Configuration.getMongoConnection()
d2sec = db.d2sec
info = db.info

# make parser
parser = make_parser()
ch = ExploitHandler()
parser.setContentHandler(ch)
# check modification date
try:
    f = urlopen(d2securl)
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(d2securl))
i = info.find_one({'db': 'd2sec'})
if i is not None:
    if f.headers['last-modified'] == i['last-modified']:
        sys.exit("Not modified")
# parse xml and store in database
parser.parse(f)
bulk = d2sec.initialize_ordered_bulk_op()
for exploit in progressbar(ch.d2sec):
    print (exploit)
    if args.v:
        print (exploit)
    bulk.find({'id': exploit['id']}).upsert().update({"$set": {'id': exploit['id'], 'url': exploit['url'], 'name': exploit['name']}})
bulk.execute()

#update database info after successful program-run
info.update({'db': 'd2sec'}, {"$set": {'last-modified': f.headers['last-modified']}}, upsert=True)

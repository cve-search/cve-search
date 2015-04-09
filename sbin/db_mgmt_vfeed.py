#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Import vFeed CVE cross-references into vfeed collection.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2013-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from urllib.request import urlopen
import tarfile
import shutil
import sqlite3

from lib.ProgressBar import progressbar
from lib.Config import Configuration

vFeedurl = Configuration.getvFeedURL()
vFeedstatus = Configuration.getvFeedStatus()

# connect to db
db = Configuration.getMongoConnection()
info = db.info
# check modification date
try:
    u = urlopen(vFeedurl)
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(vFeedurl))
i = info.find_one({'db': 'vfeed'})
if i is not None:
    if u.headers['last-modified'] == i['last-modified']:
        sys.exit("Not modified")
# create temp file and download and unpack database
if not os.path.exists('./tmp'):
    os.mkdir('./tmp')
with open('./tmp/vfeed.db.tgz', 'wb') as fp:
    shutil.copyfileobj(u, fp)
t = tarfile.open(name='./tmp/vfeed.db.tgz', mode='r')
t.extract('vfeed.db', path='./tmp/')
t.close

# excluded map_cve_milw0rm because it moved to a different domain, thus the id is irrelevant.
# Talked about this with Toolswatch dev, he's going to take a look, so leave this comment in until further notice
vfeedmap = ['map_cve_exploitdb', 'map_cve_openvas', 'map_cve_fedora',
            'map_cve_osvdb', 'map_cve_gentoo', 'map_cve_oval', 'map_cve_iavm',
            'map_cve_redhat', 'map_cve_mandriva', 'map_cve_saint',
            'map_cve_scip', 'map_cve_aixapar', 'map_cve_ms', 'map_cve_suse',
            'map_cve_certvn', 'map_cve_msf', 'map_cve_ubuntu', 'map_cve_cisco',
            'map_cve_mskb', 'map_redhat_bugzilla', 'map_cve_debian', 'map_cve_nmap',
            'map_cve_nessus', 'map_cve_vmware', 'map_cve_suricata',
            'map_cve_hp', 'map_cve_bid', 'map_cve_snort']

# connect to sqlite database
con = sqlite3.connect('./tmp/vfeed.db')
con.text_factory = lambda x: x.decode("utf-8", "ignore")
c = con.cursor()
vfeed = db.vfeed

# read sqlite database and store in mongo database
for vmap in progressbar(vfeedmap):
    e = c.execute('SELECT * FROM %s' % vmap)
    names = list(map(lambda x: x[0], e.description))
    bulk = vfeed.initialize_ordered_bulk_op()
    for r in e:
        try:
            if vmap == 'map_redhat_bugzilla':
                icveid = names.index('redhatid')
            else:
                icveid = names.index("cveid")
        except Exception as ex:
            sys.exit('Exeption in %s: %s' % (vmap, ex))
            continue
        mapArray={}
        for i in range(0,len(r)):
            if not (names[i] == "cveid"):
                mapArray[str(names[i])]=str(r[i])
        if not vmap=='map_redhat_bugzilla':
            bulk.find({'id': r[icveid]}).upsert().update({"$set":{vmap:mapArray}})
        else:
            bulk.find({'map_cve_redhat.redhatid': r[icveid]}).update({"$set":{vmap:mapArray}})
    bulk.execute()

#update database info after successful program-run
info.update({'db': 'vfeed'}, {"$set": {'last-modified': u.headers['last-modified']}}, upsert=True)

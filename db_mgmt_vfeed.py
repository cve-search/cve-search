#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
#
# Import vFeed CVE cross-references into vfeed collection.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2013 Alexandre Dulaunoy - a@foo.be

from urllib.request import urlopen
import pymongo
import sys
import tarfile
import os.path
import shutil
import sqlite3

vFeedurl = 'http://www.toolswatch.org/vfeed/vfeed.db.tgz'
vFeedstatus = 'http://www.toolswatch.org/update.dat'

connect = pymongo.Connection()
db = connect.cvedb
info = db.info

u = urlopen(vFeedurl)
i = info.find_one({'db': 'vfeed'})
if i is not None:
    if u.headers['last-modified'] == i['last-modified']:
        sys.exit("Not modified")
info.update({'db': 'vfeed'}, {"$set":{'last-modified': u.headers['last-modified']}}, upsert=True)

if not os.path.exists('./tmp'):
    os.mkdir('./tmp')

with open('./tmp/vfeed.db.tgz', 'wb') as fp:
    shutil.copyfileobj(u, fp)

t = tarfile.open(name='./tmp/vfeed.db.tgz', mode='r')
t.extract('vfeed.db',path='./tmp/')
t.close

vfeedmap = ['map_cve_exploitdb', 'map_cve_openvas', 'map_cve_fedora',
'map_cve_osvdb', 'map_cve_gentoo', 'map_cve_oval', 'map_cve_iavm',
'map_cve_redhat', 'map_cve_mandriva', 'map_cve_saint', 'map_cve_milw0rm',
'map_cve_scip', 'map_cve_aixapar', 'map_cve_ms', 'map_cve_suse',
'map_cve_certvn', 'map_cve_msf', 'map_cve_ubuntu', 'map_cve_cisco',
'map_cve_mskb', 'map_redhat_bugzilla', 'map_cve_debian',
'map_cve_debian', 'map_cve_nessus', 'map_cve_vmware', 'map_cve_suricata',
'map_cve_hp', 'map_cve_bid']

con = sqlite3.connect('./tmp/vfeed.db')
con.text_factory = lambda x: x.decode("utf-8","ignore")
c = con.cursor()
connect = pymongo.Connection()
cvedb = connect.cvedb
vfeed = cvedb.vfeed

for vmap in vfeedmap:
    e = c.execute('SELECT * FROM %s' % vmap)
    names = list(map(lambda x: x[0], e.description))
    for r in e:
        try:
            icveid = names.index("cveid")
        except:
            continue
        for i in range(0,len(r)):
            if not (names[i] == "cveid"):
                entry = vfeed.find(({'id': r[icveid]}))
                k = vmap+"_"+str(names[i])
                if entry.count() > 0:
                    vfeed.update({'id': r[icveid]}, {"$set":{k: str(r[i])}})
                else:
                    vfeed.insert({'id': r[icveid], k: str(r[i])})

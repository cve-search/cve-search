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

import tarfile
import shutil
import sqlite3

from lib.ProgressBar import progressbar
from lib.Config import Configuration
import lib.DatabaseLayer as db

vFeedurl = Configuration.getvFeedURL()
vFeedstatus = Configuration.getvFeedStatus()
tmppath = os.path.join(runPath, "..", Configuration.getTmpdir())

# check modification date
try:
    u = Configuration.getFile(vFeedurl)
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(vFeedurl))
i = db.getLastModified('vfeed')
if i is not None:
    if u.headers['last-modified'] == i:
        print("Not modified")
        sys.exit(0)
# create temp file and download and unpack database
if not os.path.exists(tmppath):
    os.mkdir(tmppath)
with open(tmppath+'/vfeed.db.tgz', 'wb') as fp:
    shutil.copyfileobj(u, fp)
t = tarfile.open(name=tmppath+'/vfeed.db.tgz', mode='r')
t.extract('vfeed.db', path=tmppath)
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

db.bulkvFeedUpdate(tmppath, vfeedmap)

#update database info after successful program-run
db.setColUpdate('vfeed', u.headers['last-modified'])

#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Simple web interface to cve-search to display the last entries
# and view a specific CVE.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2013 Alexandre Dulaunoy - a@foo.be

from flask import Flask
from flask import render_template, url_for
from flask.ext.pymongo import PyMongo
import sys
sys.path.append("../lib/")
import cves
import redis
import pymongo

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['MONGO_DBNAME'] = 'cvedb'
mongo = PyMongo(app)

@app.route('/cve/<cveid>')
def cve(cveid):
    cvesp = cves.last(rankinglookup = True, namelookup = True, vfeedlookup = True)
    cve = cvesp.getcve(cveid=cveid)
    if cve is None:
        return page_not_found(404)
    return render_template('cve.html', cve=cve)

@app.route('/')
def last():
    cvesp = cves.last(rankinglookup = True, namelookup = True, vfeedlookup = True)
    cve = cvesp.get(limit=50)

    return render_template('index.html', cve=cve, r=0)

@app.route('/r/<int:r>')
def lastrange(r):
    if not r:
        r = 0
    cvesp = cves.last(rankinglookup = True, namelookup = True, vfeedlookup = True)
    cve = cvesp.get(limit=60, skip=r)
    return render_template('index.html', cve=cve, r=r)

@app.route('/browse/<vendor>/<product>')
@app.route('/browse/<vendor>')
@app.route('/browse/')
def browse(vendor=None,product=None):
    r = redis.StrictRedis(host='localhost', port=6379, db=10)
    if vendor is None:
        v1 = r.smembers("t:/o")
        v2 = r.smembers("t:/a")
        v3 = r.smembers("t:/h")
        vendor = sorted(list(set(list(v1)+list(v2)+list(v3))))
        cpe=None
    else:
        cpenum = r.scard("v:"+vendor)
        if cpenum < 1:
            return page_not_found(404)
        p = r.smembers("v:"+vendor)
        cpe = sorted(list(p))

    return render_template('browse.html', cpe=cpe, vendor=vendor, product=product)

@app.route('/search/<vendor>/<product>')
def search(vendor=None,product=None):

    connect = pymongo.Connection()
    db = connect.cvedb
    collection = db.cves
    search = vendor+":"+product
    cve = collection.find({"vulnerable_configuration": {'$regex': search}}).sort("last-modified",1)
    return render_template('search.html', cve=cve)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
        app.run(debug=True)

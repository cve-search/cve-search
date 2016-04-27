#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Simple web interface to cve-search to display the last entries
# and view a specific CVE.
#
# Software is free software released under the "Modified BSD license"
#

# Copyright (c) 2013-2015 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import os
import sys
_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from flask import Flask, render_template, request, jsonify
from redis import exceptions as redisExceptions

import json
import re
import argparse
import time
import urllib
import random
import signal
import logging
from logging.handlers import RotatingFileHandler

from lib.Config import Configuration
from lib.Toolkit import toStringFormattedCPE, toOldCPE, currentTime, isURL, vFeedName, convertDateToDBFormat
import lib.CVEs as cves
import lib.DatabaseLayer as dbLayer

# parse command line arguments
argparser = argparse.ArgumentParser(description='Start CVE-Search web component')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()

# variables
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['MONGO_DBNAME'] = Configuration.getMongoDB()
app.config['SECRET_KEY'] = str(random.getrandbits(256))
pageLength = Configuration.getPageLength()

# db connectors
redisdb = Configuration.getRedisVendorConnection()

# functions
def getBrowseList(vendor):
    result = {}
    if (vendor is None) or type(vendor) == list:
        v1 = redisdb.smembers("t:/o")
        v2 = redisdb.smembers("t:/a")
        v3 = redisdb.smembers("t:/h")
        vendor = sorted(list(set(list(v1) + list(v2) + list(v3))))
        cpe = None
    else:
        cpenum = redisdb.scard("v:" + vendor)
        if cpenum < 1:
            return page_not_found(404)
        p = redisdb.smembers("v:" + vendor)
        cpe = sorted(list(p))
    result["vendor"] = vendor
    result["product"] = cpe
    return result


def getVersionsOfProduct(product):
    p = redisdb.smembers("p:" + product)
    return sorted(list(p))


def filter_logic(unlisted, timeSelect, startDate, endDate,
                 timeTypeSelect, cvssSelect, cvss, rejectedSelect, limit, skip):
    query = []
    # retrieving lists
    if rejectedSelect == "hide":
        exp = "^(?!\*\* REJECT \*\*\s+DO NOT USE THIS CANDIDATE NUMBER.*)"
        query.append({'summary': re.compile(exp)})
    # cvss logic
    if cvssSelect != "all":
        if cvssSelect == "above":
            query.append({'cvss': {'$gt': float(cvss)}})
        if cvssSelect == "equals":
            query.append({'cvss': float(cvss)})
        if cvssSelect == "below":
            query.append({'cvss': {'$lt': float(cvss)}})
    # date logic
    if timeSelect != "all":
        startDate = convertDateToDBFormat(startDate)
        endDate = convertDateToDBFormat(endDate)
        if timeSelect == "from":
            query.append({timeTypeSelect: {'$gt': startDate}})
        if timeSelect == "until":
            query.append({timeTypeSelect: {'$lt': endDate}})
        if timeSelect == "between":
            query.append({timeTypeSelect: {'$gt': startDate, '$lt': endDate}})
        if timeSelect == "outside":
            query.append({'$or': [{timeTypeSelect: {'$lt': startDate}}, {timeTypeSelect: {'$gt': endDate}}]})
    return dbLayer.getCVEs(limit=limit, skip=skip, query=query)

# routes
@app.route('/')
def index():
    # get default page on HTTP get (navigating to page)
    unlisted = "show"
    timeSelect = "all"
    startDate = None
    endDate = None
    timeTypeSelect = "Modified"
    cvssSelect = "all"
    cvss = None
    rejectedSelect = "hide"
    cve = filter_logic(unlisted, timeSelect, startDate, endDate,
                       timeTypeSelect, cvssSelect, cvss, rejectedSelect, pageLength, 0)
    return render_template('index-minimal.html', cve=cve, r=0, pageLength=pageLength,  minimal=True)

@app.route('/', methods=['POST'])
def filterPost():
    unlisted = request.form.get('unlistedSelect')
    timeSelect = request.form.get('timeSelect')
    startDate = request.form.get('startDate')
    endDate = request.form.get('endDate')
    timeTypeSelect = request.form.get('timeTypeSelect')
    cvssSelect = request.form.get('cvssSelect')
    cvss = request.form.get('cvss')
    rejectedSelect = request.form.get('rejectedSelect')
    settings = {'unlistedSelect': unlisted, 'timeSelect': timeSelect,
                'startDate': startDate, 'endDate': endDate,
                'timeTypeSelect': timeTypeSelect, 'cvssSelect': cvssSelect,
                'cvss': cvss, 'rejectedSelect': rejectedSelect}
    # retrieving data
    cve = filter_logic(unlisted, timeSelect, startDate, endDate,
                       timeTypeSelect, cvssSelect, cvss, rejectedSelect, pageLength, 0)
    return render_template('index-minimal.html', settings=settings, cve=cve, r=0, pageLength=pageLength,  minimal=True)


@app.route('/r/<int:r>', methods=['POST', 'GET'])
def filterLast(r):
    if not r:
        r = 0
    blacklist = request.form.get('blacklistSelect')
    whitelist = request.form.get('whitelistSelect')
    unlisted = request.form.get('unlistedSelect')
    timeSelect = request.form.get('timeSelect')
    startDate = request.form.get('startDate')
    endDate = request.form.get('endDate')
    timeTypeSelect = request.form.get('timeTypeSelect')
    cvssSelect = request.form.get('cvssSelect')
    cvss = request.form.get('cvss')
    rejectedSelect = request.form.get('rejectedSelect')
    settings = {'blacklistSelect': blacklist, 'whitelistSelect': whitelist,
                'unlistedSelect': unlisted, 'timeSelect': timeSelect,
                'startDate': startDate, 'endDate': endDate,
                'timeTypeSelect': timeTypeSelect, 'cvssSelect': cvssSelect,
                'cvss': cvss, 'rejectedSelect': rejectedSelect}
    # retrieving data
    cve = filter_logic(unlisted, timeSelect, startDate, endDate,
                       timeTypeSelect, cvssSelect, cvss, rejectedSelect, pageLength, r)
    return render_template('index-minimal.html', settings=settings, cve=cve, r=r, pageLength=pageLength, minimal=True)

@app.route('/api/cpe2.3/<path:cpe>', methods=['GET'])
def cpe23(cpe):
    cpe = toStringFormattedCPE(cpe)
    if not cpe: cpe='None'
    return cpe

@app.route('/api/cpe2.2/<path:cpe>', methods=['GET'])
def cpe22(cpe):
    cpe = toOldCPE(cpe)
    if not cpe: cpe='None'
    return cpe

@app.route('/api/cvefor/<path:cpe>', methods=['GET'])
def apiCVEFor(cpe):
    cpe=urllib.parse.unquote_plus(cpe)
    cpe=toStringFormattedCPE(cpe)
    if not cpe: cpe='None'
    r = []
    cvesp = cves.last(rankinglookup=False, namelookup=False, vfeedlookup=True, capeclookup=False)
    for x in dbLayer.cvesForCPE(cpe):
        r.append(cvesp.getcve(x['id']))
    return json.dumps(r)

@app.route('/api/cve/<cveid>', methods=['GET'])
def apiCVE(cveid):
    cvesp = cves.last(rankinglookup=True, namelookup=True, vfeedlookup=True, capeclookup=True)
    cve = cvesp.getcve(cveid=cveid)
    if cve is None:
        cve = {}
    return (jsonify(cve))

@app.route('/api/browse/<vendor>', methods=['GET'])
@app.route('/api/browse/', methods=['GET'])
@app.route('/api/browse', methods=['GET'])
def apibrowse(vendor=None):
    if vendor is not None:
        vendor = urllib.parse.quote_plus(vendor).lower()
    browseList = getBrowseList(vendor)
    if isinstance(browseList, dict):
        return (jsonify(browseList))
    else:
        return (jsonify({}))

@app.route('/api/last/', methods=['GET'])
@app.route('/api/last', methods=['GET'])
def apilast():
    limit = 30
    cvesp = cves.last(rankinglookup=True, namelookup=True, vfeedlookup=True, capeclookup=True)
    cve = cvesp.get(limit=limit)
    return (jsonify({"results": cve} ))

@app.route('/api/search/<vendor>/<path:product>', methods=['GET'])
def apisearch(vendor=None, product=None):
    if vendor is None or product is None:
        return (jsonify({}))
    search = vendor + ":" + product
    return (json.dumps(dbLayer.cvesForCPE(search)))

@app.route('/cve/<cveid>')
def cve(cveid):
    cveid = cveid.upper()
    cvesp = cves.last(rankinglookup=True, namelookup=True, vfeedlookup=True, capeclookup=True, subscorelookup=True, misplookup=True)
    cve = cvesp.getcve(cveid=cveid)
    if cve is None:
        return render_template('error.html',status={'except':'cve-not-found','info':{'cve':cveid}},minimal=True)
    return render_template('cve.html', cve=cve, minimal=True)

@app.route('/api/dbInfo', methods=['GET'])
def apidbInfo():
    return (json.dumps(dbLayer.getDBStats()))

@app.route('/browse/<vendor>')
@app.route('/browse/')
def browse(vendor=None):
    try:
        if vendor is not None:
            vendor = urllib.parse.quote_plus(vendor).lower()
        browseList = getBrowseList(vendor)
        vendor = browseList["vendor"]
        product = browseList["product"]
        return render_template('browse.html', product=product, vendor=vendor, minimal=True)
    except redisExceptions.ConnectionError:
        return render_template('error.html',
                               status={'except':'redis-connection',
                                       'info':{'host':Configuration.getRedisHost(),'port':Configuration.getRedisPort()}})

@app.route('/cwe')
def cwe():
    cwes=[x for x in dbLayer.getCWEs() if x["weaknessabs"].lower()=="class"]
    return render_template('cwe.html', cwes=cwes, capec=None, minimal=True)

@app.route('/cwe/<cweid>')
def relatedCWE(cweid):
    cwes={x["id"]: x["name"] for x in dbLayer.getCWEs()}
    return render_template('cwe.html', cwes=cwes, cwe=cweid, capec=dbLayer.getCAPECFor(cweid), minimal=True)

@app.route('/capec/<capecid>')
def capec(capecid):
    cwes={x["id"]: x["name"] for x in dbLayer.getCWEs()}
    return render_template('capec.html', cwes=cwes, capec=dbLayer.getCAPEC(capecid), minimal=True)

@app.route('/search', methods=['POST'])
def searchText():
    search = request.form.get('search')
    result = dbLayer.getSearchResults(search)
    cve=result['data']
    errors=result['errors'] if 'errors' in result else []
    return render_template('search.html', cve=cve, errors=errors, minimal=True)


@app.route('/search/<vendor>/<path:product>')
def search(vendor=None, product=None):
    search = vendor + ":" + product
    cve = dbLayer.cvesForCPE(search)
    return render_template('search.html', vendor=vendor, product=product, cve=cve, minimal=True)

@app.route('/link/<vFeedMap>/<field>/<path:value>')
def link(vFeedMap=None,field=None,value=None):
    vFeedMap=htmlDedode(vFeedMap)
    field=htmlDedode(field)
    value=htmlDedode(value)
    search="%s.%s"%(vFeedMap,field)
    regex = re.compile(re.escape(value), re.I)
    cve=dbLayer.vFeedLinked(search, regex)
    cvssList=[float(x['cvss']) for x in cve if 'cvss' in x]
    if cvssList:
        stats={'maxCVSS': max(cvssList), 'minCVSS': min(cvssList),'count':len(cve)}
    else:
        stats={'maxCVSS': 0, 'minCVSS': 0, 'count':len(cve)}
    return render_template('linked.html', vFeedMap=vFeedMap, field=field, value=value, cve=cve, stats=stats, minimal=True)

# error handeling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', minimal=True), 404


# filters
@app.template_filter('currentTime')
def currentTimeFilter(utc):
    return currentTime(utc)


@app.template_filter('htmlDecode')
def htmlDedode(string):
    return urllib.parse.unquote_plus(string)


@app.template_filter('htmlEncode')
def htmlEncode(string):
    return urllib.parse.quote_plus(string).lower()


@app.template_filter('isURL')
def isURLFilter(string):
    return isURL(string)

@app.template_filter('vFeedName')
def vFeedNameFilter(string):
    return vFeedName(string)

@app.template_filter('sortIntLikeStr')
def sortIntLikeStrFilter(datalist):
    return sorted(datalist, key=lambda k: int(k))

# signal handlers
def sig_handler(sig, frame):
    print('Caught signal: %s' % sig)
    IOLoop.instance().add_callback(shutdown)


def shutdown():
    MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 3
    print('Stopping http server')
    http_server.stop()

    print('Will shutdown in %s seconds ...' % MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
    io_loop = IOLoop.instance()
    deadline = time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN

    def stop_loop():
        now = time.time()
        if now < deadline and (io_loop._callbacks or io_loop._timeouts):
            io_loop.add_timeout(now + 1, stop_loop)
        else:
            io_loop.stop()
            print('Shutdown')
    stop_loop()

if __name__ == '__main__':
    # get properties
    flaskHost = Configuration.getFlaskHost()
    flaskPort = Configuration.getFlaskPort()
    flaskDebug = Configuration.getFlaskDebug()
    # logging
    if Configuration.getLogging():
        logfile = Configuration.getLogfile()
        pathToLog = logfile.rsplit('/', 1)[0]
        if not os.path.exists(pathToLog):
            os.makedirs(pathToLog)
        maxLogSize = Configuration.getMaxLogSize()
        backlog = Configuration.getBacklog()
        file_handler = RotatingFileHandler(logfile, maxBytes=maxLogSize, backupCount=backlog)
        file_handler.setLevel(logging.ERROR)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)

    if flaskDebug:
        # start debug flask server
        app.run(host=flaskHost, port=flaskPort, debug=flaskDebug)
    else:
        # start asynchronous server using tornado wrapper for flask
        # ssl connection
        print("Server starting...")
        if Configuration.useSSL():
            cert = os.path.join(_runPath, "../", Configuration.getSSLCert())
            key = os.path.join(_runPath, "../", Configuration.getSSLKey())
            ssl_options = {"certfile": cert,
                           "keyfile": key}
        else:
            ssl_options = None
        signal.signal(signal.SIGTERM, sig_handler)
        signal.signal(signal.SIGINT, sig_handler)
        global http_server
        http_server = HTTPServer(WSGIContainer(app), ssl_options=ssl_options)
        http_server.bind(flaskPort, address=flaskHost)
        http_server.start(0)  # Forks multiple sub-processes
        IOLoop.instance().start()

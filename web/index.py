#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Simple web interface to cve-search to display the last entries
# and view a specific CVE.
#
# Software is free software released under the "Modified BSD license"
#

# Copyright (c) 2013-2014 Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014      Pieter-Jan Moreels - pieterjan.moreels@gmail.com
from flask import Flask
from flask import render_template, url_for, request
from flask.ext.pymongo import PyMongo
import pymongo
import sys
sys.path.append("../lib/")
import cves
import redis
import pymongo
from datetime import datetime
from dateutil import tz
import dateutil.parser
import os
import base64
import re
import argparse
import time
sys.path.append("..")
from db_whitelist import *
from db_blacklist import *

# parse command line arguments
argparser = argparse.ArgumentParser(description='populate/update the whitelist used in webviews')
argparser.add_argument('-v', action='store_true', help='verbose output')
args = argparser.parse_args()

# variables
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['MONGO_DBNAME'] = 'cvedb'
mongo = PyMongo(app)

# functions
def matchFilePath(path):
    pattern = re.compile('^([a-zA-Z/ 0-9._-])+$')
    if pattern.match(path):
        return True
    else:
        return False

def getBrowseList(vendor):
    r = redis.StrictRedis(host='localhost', port=6379, db=10)
    result = {}
    if (vendor is None) or type(vendor) == list:
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
    result["vendor"]=vendor
    result["product"]=cpe
    return result

def getWhitelist():
    connect = pymongo.Connection()
    db = connect.cvedb
    collection = db.mgmt_whitelist
    whitelist = collection.find()
    return whitelist

def getWhitelistRules():
    connect = pymongo.Connection()
    db = connect.cvedb
    collection = db.mgmt_whitelist
    whitelist = collection.distinct('id')
    return whitelist

def whitelist_mark(cve):
    whitelist = getWhitelistRules()
    whitelistitems = []
    # ensures we're working with a list object, in case we get a pymongo.cursor object
    cve = list(cve)
    for whitelistid in whitelist:
        whitelistitems.append(whitelistid)
    # check the cpes (full or partially) in the whitelist
    for cveid in cve:
        cpes=cveid['vulnerable_configuration']
        if len([i for e in whitelistitems for i in cpes if e in i])>0:
            cve[cve.index(cveid)]['whitelisted'] = 'yes'
    return cve

def blacklist_mark(cve):
    blacklist = getBlacklistRules()
    blacklistitems = []
    # ensures we're working with a list object, in case we get a pymongo.cursor object
    cve = list(cve)
    for blacklistid in blacklist:
        blacklistitems.append(blacklistid)
    # check the cpes (full or partially) in the blacklist
    for cveid in cve:
        cpes=cveid['vulnerable_configuration']
        if len([i for e in blacklistitems for i in cpes if e in i])>0:
            cve[cve.index(cveid)]['blacklisted'] = 'yes'
    return cve

def getBlacklist():
    connect = pymongo.Connection()
    db = connect.cvedb
    collection = db.mgmt_blacklist
    blacklist = collection.find()
    return blacklist

def getBlacklistRules():
    connect = pymongo.Connection()
    db = connect.cvedb
    collection = db.mgmt_blacklist
    blacklist = collection.distinct('id')
    return blacklist

def getBlacklistRegexes():
    blacklist = getBlacklistRules()
    regexes = []
    for blacklistRule in blacklist:
        regexes.append(re.compile(blacklistRule))
    return regexes

def getWhitelistRegexes():
    whitelist = getWhitelistRules()
    regexes = []
    for whitelistRule in whitelist:
        regexes.append(re.compile(whitelistRule))
    return regexes

def getCVEBlacklisted(limit, skip):
    connect = pymongo.Connection()
    db = connect.cvedb
    collection = db.cves
    regexes = getBlacklistRegexes()
    cves = collection.find({'vulnerable_configuration':{'$nin':regexes}}).sort("Modified", -1).limit(limit).skip(skip)
    return cves

def addCPEToList(cpe, listType):
    if listType.lower() in ("blacklist", "black", "b", "bl"):
        if insertBlacklist(cpe):
            return True
        else:
            return False
    if listType.lower() in ("whitelist", "white", "w", "wl"):
        if insertWhitelist(cpe):
            return True
        else:
            return False

def getVersionsOfProduct(product):
    r = redis.StrictRedis(host='localhost', port=6379, db=10)
    p = r.smembers("p:"+product)
    return sorted(list(p))

def convertDateToDBFormat(string):
    result = None
    try:
        result = time.strptime(string, "%d-%m-%Y")
    except:
        pass
    try:
        result = time.strptime(string, "%d-%m-%y")
    except:
        pass
    try:
        result = time.strptime(string, "%d/%m/%Y")
    except:
        pass
    try:
        result = time.strptime(string, "%d/%m/%y")
    except:
        pass
    if result != None:
        result = time.strftime('%Y-%m-%d', result)
    return result

def filter_logic(blacklist, whitelist, unlisted, timeSelect, startDate, endDate, timeTypeSelect, cvssSelect, cvss, limit, skip):
    connect = pymongo.Connection()
    db = connect.cvedb
    collection = db.cves

    query = []
    # retrieving lists
    if blacklist == "on":
        regexes = getBlacklistRegexes()
        query.append({'vulnerable_configuration':{'$nin':regexes}})
    if whitelist == "hide":
        regexes = getWhitelistRegexes()
        query.append({'vulnerable_configuration':{'$nin':regexes}})
    if unlisted == "hide":
        wlregexes = getWhitelistRegexes()
        blregexes = getBlacklistRegexes()
        query.append({'$or':[{'vulnerable_configuration':{'$in':wlregexes}},{'vulnerable_configuration':{'$in':blregexes}}]})
    # cvss logic
    if cvssSelect != "all":
        if cvssSelect == "above":
            query.append({'cvss':{'$gt':float(cvss)}})
        if cvssSelect == "equals":
            query.append({'cvss':float(cvss)})
        if cvssSelect == "below":
            query.append({'cvss':{'$lt':float(cvss)}})
    # date logic
    if timeSelect != "all":
        print(startDate)
        startDate = convertDateToDBFormat(startDate)
        print(startDate)
        endDate = convertDateToDBFormat(endDate)
        if timeSelect == "from":
            query.append({timeTypeSelect:{'$gt':startDate}})
        if timeSelect == "until":
            query.append({timeTypeSelect:{'$lt':endDate}})
        if timeSelect == "between":
            query.append({timeTypeSelect:{'$gt':startDate, '$lt':endDate}})
        if timeSelect == "outside":
            query.append({'$or':[{timeTypeSelect:{'$lt':startDate}},{timeTypeSelect:{'$gt':endDate}}]})
    if len(query) ==0:
        cve = collection.find().sort("Modified", -1).limit(limit).skip(skip)
    elif len(query) == 1:
        cve = collection.find(query[0]).sort("Modified", -1).limit(limit).skip(skip)
    else:
        cve = collection.find({'$and':query}).sort("Modified", -1).limit(limit).skip(skip)
    # marking relevant records
    if whitelist == "on":
        cve = whitelist_mark(cve)
    if blacklist == "mark":
        cve = cve = blacklist_mark(cve)
    cve = list(cve)
    return cve

#routes
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
    cve = cvesp.get(limit=50, skip=r)
    return render_template('index.html', cve=cve, r=r)  

@app.route('/cve/<cveid>')
def cve(cveid):
    cvesp = cves.last(rankinglookup = True, namelookup = True, vfeedlookup = True)
    cve = cvesp.getcve(cveid=cveid)
    if cve is None:
        return page_not_found(404)
    return render_template('cve.html', cve=cve)

@app.route('/browse/<vendor>')
@app.route('/browse/')
def browse(vendor=None):
    browseList = getBrowseList(vendor)
    vendor = browseList["vendor"]
    product = browseList["product"]
    return render_template('browse.html', product=product, vendor=vendor)

@app.route('/search/<vendor>/<product>')
def search(vendor=None,product=None):
    connect = pymongo.Connection()
    db = connect.cvedb
    collection = db.cves
    search = vendor+":"+product
    cve = collection.find({"vulnerable_configuration": {'$regex': search}}).sort("Modified",-1)
    return render_template('search.html', vendor=vendor, product=product, cve=cve)

@app.route('/whitelist')
def whitelist():
    cve=getCVEBlacklisted(50,0)
    cve=whitelist_mark(cve)
    return render_template('whitelist.html', cve=cve, r=0)

@app.route('/whitelist/r/<int:r>')
def whitelistlast(r):
    if not r:
        r = 0
    cve=getCVEBlacklisted(50,r)
    cve=whitelist_mark(cve)
    return render_template('whitelist.html', cve=cve, r=r)

@app.route('/filter')
def filter():
    # get default page on HTTP get (navigating to page)
    cve=getCVEBlacklisted(50,0)
    cve=whitelist_mark(cve)
    return render_template('filter.html',cve=cve, r=0)

@app.route('/filter', methods = ['POST'])
def filterPost():
    blacklist=request.form.get('blacklistSelect')
    whitelist=request.form.get('whitelistSelect')
    unlisted=request.form.get('unlistedSelect')
    timeSelect=request.form.get('timeSelect')
    startDate=request.form.get('startDate')
    endDate=request.form.get('endDate')
    timeTypeSelect=request.form.get('timeTypeSelect')
    cvssSelect=request.form.get('cvssSelect')
    cvss=request.form.get('cvss')
    settings = {'blacklistSelect':blacklist,'whitelistSelect':whitelist,'unlistedSelect':unlisted,'timeSelect':timeSelect,'startDate':startDate,'endDate':endDate,'timeTypeSelect':timeTypeSelect,'cvssSelect':cvssSelect,'cvss':cvss}
    # retrieving data
    cve = filter_logic(blacklist, whitelist, unlisted, timeSelect, startDate, endDate, timeTypeSelect, cvssSelect, cvss, 50, 0)
    return render_template('filter.html', settings=settings, cve=cve, r=0)

@app.route('/filter/r/<int:r>', methods = ['POST'])
def filterLast(r):
    if not r:
        r = 0
    blacklist=request.form.get('blacklistSelect')
    whitelist=request.form.get('whitelistSelect')
    unlisted=request.form.get('unlistedSelect')
    timeSelect=request.form.get('timeSelect')
    startDate=request.form.get('startDate')
    endDate=request.form.get('endDate')
    timeTypeSelect=request.form.get('timeTypeSelect')
    cvssSelect=request.form.get('cvssSelect')
    cvss=request.form.get('cvss')
    settings = {'blacklistSelect':blacklist,'whitelistSelect':whitelist,'unlistedSelect':unlisted,'timeSelect':timeSelect,'startDate':startDate,'endDate':endDate,'timeTypeSelect':timeTypeSelect,'cvssSelect':cvssSelect,'cvss':cvss}
    # retrieving data
    cve = filter_logic(blacklist, whitelist, unlisted, timeSelect, startDate, endDate, timeTypeSelect, cvssSelect, cvss, 50, r)

    return render_template('filter.html', settings=settings, cve=cve, r=r)

@app.route('/admin')
def admin():
    status=["default","none"]
    return render_template('admin.html', status=status)

@app.route('/admin/updatedb')
def updatedb():
    os.system("cd ..; python3 db_updater.py -civ")
    status = ["db_updated","success"]
    return render_template('admin.html', status=status)

@app.route('/admin/whitelist/import', methods = ['POST'])
def whitelistImport(force=None, path=None):
    path = request.form.get('file')
    force = request.form.get('force')
    if (matchFilePath(path)):
        if os.path.isfile(path):
            count = countWhitelist()
            if (count == 0) | (not count) | (force == "f"):
                dropWhitelist()
                importWhitelist(path)
                status=["wl_imported","success"]
            else:
                status=["wl_already_filled","info"]
        else:
            status=["invalid_path","error"]
    else:
        status=["invalid_path_format","error"]
    return render_template('admin.html', status=status)

@app.route('/admin/whitelist/export', methods = ['POST'])
def whitelistExport(force=None, path=None):
    path = request.form.get('file')
    force = request.form.get('force')
    if (matchFilePath(path)):
        if (force=="df") and (os.path.isfile(path)):
            status=["wl_file_already_exists","warning"]
        else:
            exportBlacklist(path)
            status=["wl_exported","success"]
    else:
        status=["invalid_path","error"]
    return render_template('admin.html', status=status)

@app.route('/admin/whitelist/drop')
def whitelistDrop():
    dropWhitelist()
    status=["wl_dropped","success"]
    return render_template('admin.html', status=status)

@app.route('/admin/whitelist/view')
def whitelistView():
    whitelist = getWhitelist()
    status=["default","none"]
    return render_template('list.html', rules=whitelist, status=status, listType="Whitelist")

@app.route('/admin/whitelist/add', methods = ['POST'])
def whitelistAdd():
    cpe = request.form.get('cpe')
    if addCPEToList(cpe, "whitelist"):
        status=["added","success"]
    else:
        status=["already_exists","info"]
    whitelist = getWhitelist()
    return render_template('list.html', rules=whitelist, status=status, listType="Whitelist")

@app.route('/admin/whitelist/remove', methods = ['POST'])
def whitelistRemove():
    cpe = request.form.get('cpe')
    if (cpe != False):
        if (removeWhitelist(cpe) > 0):
            status=["removed","success"]
        else:
            status=["already_removed","info"]
    else:
        status=["invalid_url","error"]
    whitelist = getWhitelist()
    return render_template('list.html', rules=whitelist, status=status, listType="Whitelist")

@app.route('/admin/blacklist/import', methods = ['POST'])
def blacklistImport():
    path = request.form.get('file')
    force = request.form.get('force')
    if (matchFilePath(path)):
        if os.path.isfile(path):
            count = countBlacklist()
            if (count == 0) | (not count) | (force == "f"):
                dropBlacklist()
                importBlacklist(path)
                status=["bl_imported","success"]
            else:
                status=["bl_already_filled","info"]
        else:
            status=["invalid_path","error"]
    else:
        status=["invalid_path_format","error"]
    return render_template('admin.html', status=status)

@app.route('/admin/blacklist/export', methods = ['POST'])
def blacklistExport():
    path = request.form.get('file')
    force = request.form.get('force')
    if (matchFilePath(path)):
        if (force=="df") and (os.path.isfile(path)):
            status=["bl_file_already_exists","warning"]
        else:
            exportBlacklist(path)
            status=["bl_exported","success"]
    else:
        status=["invalid_path","error"]
    return render_template('admin.html', status=status)

@app.route('/admin/blacklist/drop')
def blacklistDrop():
    dropBlacklist()
    status=["bl_dropped","success"]
    return render_template('admin.html', status=status)

@app.route('/admin/blacklist/view')
def blacklistView():
    blacklist = getBlacklist()
    status=["default","none"]
    return render_template('list.html', rules=blacklist, status=status, listType="Blacklist")

@app.route('/admin/blacklist/add', methods = ['POST'])
def blacklistAdd(cpe=None):
    cpe = request.form.get('cpe')
    if (cpe != False):
        if insertBlacklist(cpe):
            status=["added","success"]
        else:
            status=["already_exists","info"]
    else:
        status=["invalid_url","error"]
    blacklist = getBlacklist()
    return render_template('list.html', rules=blacklist, status=status, listType="Blacklist")

@app.route('/admin/blacklist/remove', methods = ['POST'])
def blacklistRemove(cpe=None):
    cpe = request.form.get('cpe')
    if (cpe != False):
        if (removeBlacklist(cpe) > 0):
            status=["removed","success"]
        else:
            status=["already_removed","info"]
    else:
        status=["invalid_url","error"]
    blacklist = getBlacklist()
    return render_template('list.html', rules=blacklist, status=status, listType="Blacklist")

@app.route('/admin/listmanagement/add', methods = ['POST'])
def listManagementAdd():
    # retrieve the separate item parts
    item = request.form.get('item')
    listType = request.form.get('list')
    print (item)
    vendor = None
    product = None
    version = None
    pattern = re.compile('[a-z:/0-9._-]+')
    if pattern.match(item):
        item = item.split(":")
        added = False
        if len(item) == 1:
            # only vendor, so a check on cpe type is needed
            r = redis.StrictRedis(host='localhost', port=6379, db=10)
            if r.sismember("t:/o", item[0]):
                if addCPEToList("cpe:/o:"+item[0],listType):
                    added = True
            if r.sismember("t:/a", item[0]):
                if addCPEToList("cpe:/a:"+item[0], listType):
                    added = True
            if r.sismember("t:/h", item[0]):
                if addCPEToList("cpe:/h:"+item[0], listType):
                    added = True
            browseList = getBrowseList(None)
            vendor = browseList['vendor']
        elif 4 > len(item) >1:
            # cpe type can be found with a mongo regex query
            connect = pymongo.Connection()
            db = connect.cvedb
            collection = db.cpe
            result = collection.find({'id':{'$regex':item[1]}})
            if result.count() != 0:
                prefix = ((result[0])['id'])[:7]
                if len(item) == 2:
                    if addCPEToList(prefix+item[0]+":"+item[1], listType):
                        added = True
                if len(item) == 3:
                    if addCPEToList(prefix+item[0]+":"+item[1]+":"+item[2], listType):
                        added = True
            vendor = item[0]
        if len(item) > 2:
            product = item[1]
            version = getVersionsOfProduct(product)
        else:
            product = (getBrowseList(vendor))['product']
        if added:
            status=["cpe_added","success"]
        else:
            status=["cpe_not_added","error"]
    else:
        status=["invalid_cpe_format","error"]
    return render_template('listmanagement.html', status=status, listType=listType, vendor=vendor, product=product, version=version)

@app.route('/admin/listmanagement/<vendor>/<product>')
@app.route('/admin/listmanagement/<vendor>')
@app.route('/admin/listmanagement')
def listManagement(vendor=None, product=None):
    if product == None:
        # no product selected yet, so same function as /browse can be used
        browseList = getBrowseList(vendor)
        vendor = browseList["vendor"]
        product = browseList["product"]
        version = None
    else:
        # product selected, product versions required
        version = getVersionsOfProduct(product)
    status=["default","none"]
    return render_template('listmanagement.html', status=status, vendor=vendor, product=product, version=version)


# error handeling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# filters

@app.template_filter('currentTime')
def currentTime(utc):
    timezone = tz.tzlocal()
    utc = dateutil.parser.parse(utc)
    output = utc.astimezone(timezone)
    output = output.strftime('%d-%m-%Y - %H:%M')
    return output 

@app.template_filter('base64Enc')
def base64Encode(string):
    return base64.b64encode(bytes(string, "utf-8")).decode("utf-8")

if __name__ == '__main__':
        app.run(debug=True)

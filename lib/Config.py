#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Config reader to read the configuration file
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2013-2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import sys
import os
runPath = os.path.dirname(os.path.realpath(__file__))

import pymongo
import redis

import re
import datetime
import configparser
import urllib.parse
import urllib.request as req
from io import BytesIO
import gzip

class Configuration():
    ConfigParser = configparser.ConfigParser()
    ConfigParser.read(os.path.join(runPath, "../etc/configuration.ini"))
    default = {'redisHost': 'localhost', 'redisPort': 6379,
               'redisVendorDB': 10,      'redisNotificationsDB': 11,
               'redisRefDB': 12,
               'mongoHost': 'localhost', 'mongoPort': 27017,
               'mongoDB': "cvedb",
               'mongoUsername': '', 'mongoPassword': '',
               'flaskHost': "127.0.0.1", 'flaskPort': 5000,
               'flaskDebug': True,       'pageLength': 50,
               'loginRequired': False,
               'ssl': False,             'sslCertificate': "./ssl/cve-search.crt",
                                         'sslKey': "./ssl/cve-search.crt",
               'CVEStartYear': 2002,
               'vFeedurl': "http://www.toolswatch.org/vfeed/vfeed.db.tgz",
               'vFeedstatus': "http://www.toolswatch.org/update.dat",
               'cvedict': "http://static.nvd.nist.gov/feeds/xml/cve/",
               'cpedict': "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml",
               'cwedict': "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip",
               'd2sec': "http://www.d2sec.com/exploits/elliot.xml",
               'vendor': "https://nvd.nist.gov/download/vendorstatements.xml",
               'capec': "http://capec.mitre.org/data/xml/capec_v2.6.xml",
               'msbulletin': "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
               'ref': "https://cve.mitre.org/data/refs/refmap/allrefmaps.zip",
               'exploitdb': "https://github.com/offensive-security/exploit-database/raw/master/files.csv",
               'misp_url': "",            'misp_key': "",
               'logging': True,           'logfile': "./log/cve-search.log",
               'maxLogSize': '100MB',     'backlog': 5,
               'Indexdir': './indexdir',  'updatelogfile': './log/update.log',
               'Tmpdir': './tmp',
               'includeCapec': True,      'includeD2Sec': True,
               'includeVFeed': True,      'includeVendor': True,
               'includeCWE': True,
               'http_proxy': ''
               }

    @classmethod
    def readSetting(cls, section, item, default):
        result = default
        try:
            if type(default) == bool:
                result = cls.ConfigParser.getboolean(section, item)
            elif type(default) == int:
                result = cls.ConfigParser.getint(section, item)
            else:
                result = cls.ConfigParser.get(section, item)
        except:
            pass
        return result

    # Mongo
    @classmethod
    def getMongoDB(cls):
        return cls.readSetting("Mongo", "DB", cls.default['mongoDB'])

    @classmethod
    def getMongoConnection(cls):
        mongoHost = cls.readSetting("Mongo", "Host", cls.default['mongoHost'])
        mongoPort = cls.readSetting("Mongo", "Port", cls.default['mongoPort'])
        mongoDB = cls.getMongoDB()
        mongoUsername = cls.readSetting("Mongo", "Username", cls.default['mongoUsername'])
        mongoPassword = cls.readSetting("Mongo", "Password", cls.default['mongoPassword'])

        mongoUsername = urllib.parse.quote( mongoUsername )
        mongoPassword = urllib.parse.quote( mongoPassword )
        try:
            if mongoUsername and mongoPassword:
                mongoURI = "mongodb://{username}:{password}@{host}:{port}/{db}".format(
                    username = mongoUsername, password = mongoPassword,
                    host = mongoHost, port = mongoPort,
                    db = mongoDB
                )
                connect = pymongo.MongoClient(mongoURI)
            else:
                connect = pymongo.MongoClient(mongoHost, mongoPort)
        except:
            sys.exit("Unable to connect to Mongo. Is it running on %s:%s?"%(mongoHost,mongoPort))
        return connect[mongoDB]

    # Redis
    @classmethod
    def getRedisHost(cls):
        return cls.readSetting("Redis", "Host", cls.default['redisHost'])

    @classmethod
    def getRedisPort(cls):
        return cls.readSetting("Redis", "Port", cls.default['redisPort'])

    @classmethod
    def getRedisVendorConnection(cls):
        redisHost = cls.getRedisHost()
        redisPort = cls.getRedisPort()
        redisDB = cls.readSetting("Redis", "VendorsDB", cls.default['redisVendorDB'])
        return redis.StrictRedis(host=redisHost, port=redisPort, db=redisDB, charset='utf-8', decode_responses=True)

    @classmethod
    def getRedisNotificationsConnection(cls):
        redisHost = cls.getRedisHost()
        redisPort = cls.getRedisPort()
        redisDB = cls.readSetting("Redis", "NotificationsDB", cls.default['redisNotificationsDB'])
        return redis.StrictRedis(host=redisHost, port=redisPort, db=redisDB, charset="utf-8", decode_responses=True)

    @classmethod
    def getRedisRefConnection(cls):
        redisHost = cls.getRedisHost()
        redisPort = cls.getRedisPort()
        redisDB = cls.readSetting("Redis", "RefDB", cls.default['redisRefDB'])
        return redis.StrictRedis(host=redisHost, port=redisPort, db=redisDB, charset="utf-8", decode_responses=True)

    # Flask
    @classmethod
    def getFlaskHost(cls):
        return cls.readSetting("Webserver", "Host", cls.default['flaskHost'])

    @classmethod
    def getFlaskPort(cls):
        return cls.readSetting("Webserver", "Port", cls.default['flaskPort'])

    @classmethod
    def getFlaskDebug(cls):
        return cls.readSetting("Webserver", "Debug", cls.default['flaskDebug'])

    # Webserver
    @classmethod
    def getPageLength(cls):
        return cls.readSetting("Webserver", "PageLength", cls.default['pageLength'])

    @classmethod
    def loginRequired(cls):
        return cls.readSetting("Webserver", "LoginRequired", cls.default['loginRequired'])

    # SSL
    @classmethod
    def useSSL(cls):
        return cls.readSetting("Webserver", "SSL", cls.default['ssl'])

    @classmethod
    def getSSLCert(cls):
        return os.path.join(runPath, "..", cls.readSetting("Webserver", "Certificate", cls.default['sslCertificate']))

    @classmethod
    def getSSLKey(cls):
        return os.path.join(runPath, "..", cls.readSetting("Webserver", "Key", cls.default['sslKey']))

    # CVE
    @classmethod
    def getCVEStartYear(cls):
        date = datetime.datetime.now()
        year = date.year + 1
        score = cls.readSetting("CVE", "StartYear", cls.default['CVEStartYear'])
        if score < 2002 or score > year:
            print('The year %i is not a valid year.\ndefault year %i will be used.' % (score, cls.default['CVEStartYear']))
            score = cls.default['CVEStartYear']
        return cls.readSetting("CVE", "StartYear", cls.default['CVEStartYear'])

    # Sources
    @classmethod
    def getvFeedURL(cls):
        return cls.readSetting("Sources", "vFeed", cls.default['vFeedurl'])

    @classmethod
    def getvFeedStatus(cls):
        return cls.readSetting("Sources", "vFeedStatus", cls.default['vFeedstatus'])

    @classmethod
    def getRefURL(cls):
        return cls.readSetting("Sources", "Ref", cls.default['ref'])

    @classmethod
    def getCVEDict(cls):
        return cls.readSetting("Sources", "CVE", cls.default['cvedict'])

    @classmethod
    def getCPEDict(cls):
        return cls.readSetting("Sources", "CPE", cls.default['cpedict'])

    @classmethod
    def getCWEDict(cls):
        return cls.readSetting("Sources", "CWE", cls.default['cwedict'])

    @classmethod
    def getd2secDict(cls):
        return cls.readSetting("Sources", "d2sec", cls.default['d2sec'])

    @classmethod
    def getVendorDict(cls):
        return cls.readSetting("Sources", "Vendor", cls.default['vendor'])

    @classmethod
    def getCAPECDict(cls):
        return cls.readSetting("Sources", "CAPEC", cls.default['capec'])

    @classmethod
    def getMSBULLETINDict(cls):
        return cls.readSetting("Sources", "MSBULLETIN", cls.default['msbulletin'])

    @classmethod
    def getexploitdbDict(cls):
        return cls.readSetting("Sources", "exploitdb", cls.default['exploitdb'])

    # MISP
    @classmethod
    def getMISPCredentials(cls):
        url = cls.readSetting("MISP", "URL", cls.default['misp_url'])
        key = cls.readSetting("MISP", "Key", cls.default['misp_key'])
        return (url, key) if url and key else (None, None)
               
    # Logging
    @classmethod
    def getLogfile(cls):
        return os.path.join(runPath, "..", cls.readSetting("Logging", "Logfile", cls.default['logfile']))

    @classmethod
    def getUpdateLogFile(cls):
        return os.path.join(runPath, "..", cls.readSetting("Logging", "Updatelogfile", cls.default['updatelogfile']))

    @classmethod
    def getLogging(cls):
        return cls.readSetting("Logging", "Logging", cls.default['logging'])

    @classmethod
    def getMaxLogSize(cls):
        size = cls.readSetting("Logging", "MaxSize", cls.default['maxLogSize'])
        split = re.findall('\d+|\D+', size)
        try:
            if len(split) > 2 or len(split) == 0:
                raise Exception
            base = int(split[0])
            if len(split) == 1:
                multiplier = 1
            else:
                multiplier = (split[1]).strip().lower()
                if multiplier == "b":
                    multiplier = 1
                elif multiplier == "mb":
                    multiplier = 1024
                elif multiplier == "gb":
                    multiplier = 1024 * 1024
        except Exception as e:
            print(e)
            return 100 * 1024
        return base * multiplier

    @classmethod
    def getBacklog(cls):
        return cls.readSetting("Logging", "Backlog", cls.default['backlog'])

    # Indexing
    @classmethod
    def getTmpdir(cls):
        return os.path.join(runPath, "..", cls.readSetting("dbmgt", "Tmpdir", cls.default['Tmpdir']))

    # Indexing
    @classmethod
    def getIndexdir(cls):
        return os.path.join(runPath, "..", cls.readSetting("FulltextIndex", "Indexdir", cls.default['Indexdir']))

    # Enabled Feeds
    @classmethod
    def includesCapec(cls):
        return cls.readSetting("EnabledFeeds", "capec", cls.default['includeCapec'])

    @classmethod
    def includesVFeed(cls):
        return cls.readSetting("EnabledFeeds", "vFeed", cls.default['includeVFeed'])

    @classmethod
    def includesD2Sec(cls):
        return cls.readSetting("EnabledFeeds", "d2sec", cls.default['includeD2Sec'])

    @classmethod
    def includesVendor(cls):
        return cls.readSetting("EnabledFeeds", "vendor", cls.default['includeVendor'])

    @classmethod
    def includesCWE(cls):
        return cls.readSetting("EnabledFeeds", "CWE", cls.default['includeCWE'])

    @classmethod
    def includesFeed(cls, feed):
        if feed == 'capec' and not cls.includesCapec():
            return False
        elif feed == 'vfeed' and not cls.includesVFeed():
            return False
        elif feed == 'd2sec' and not cls.includesD2Sec():
            return False
        elif feed == 'vendor' and not cls.includesVendor():
            return False
        elif feed == 'cwe' and not cls.includesCWE():
            return False
        else:
            return True

    # Http Proxy
    @classmethod
    def getProxy(cls):
        return cls.readSetting("Proxy", "http", cls.default['http_proxy'])

    @classmethod
    def getFile(cls, getfile, compressed=False):
        if cls.getProxy():
            proxy = req.ProxyHandler({'http': cls.getProxy(), 'https': cls.getProxy()})
            auth = req.HTTPBasicAuthHandler()
            opener = req.build_opener(proxy, auth, req.HTTPHandler)
            req.install_opener(opener)
        if not compressed:
            return req.urlopen(getfile)
        else:
            response = req.urlopen(getfile + '.gz')
            data = None
            if 'gzip' in response.info().get('Content-Type'):
                buf = BytesIO(response.read())
                data = gzip.GzipFile(fileobj=buf)
            return (data, response)


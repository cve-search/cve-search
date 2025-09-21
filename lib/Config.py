#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Config reader to read the configuration file
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2013-2018  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import bz2
import configparser
import gzip
import json
import os
import re
import urllib.parse
import urllib.request as req
import zipfile
from io import BytesIO

import pymongo
import redis

runPath = os.path.dirname(os.path.realpath(__file__))


class Configuration:
    ConfigParser = configparser.ConfigParser()
    ConfigParser.read(
        [
            os.path.join(runPath, "../etc/configuration.ini"),
            os.path.join(runPath, "../etc/sources.ini"),
        ]
    )
    default = {
        # [Redis]
        "redisHost": "localhost",
        "redisPort": 6379,
        "redisPass": None,
        "redisVendorDB": 10,
        "redisNotificationsDB": 11,
        # [Database] (MongoDB)
        "mongoHost": "127.0.0.1",
        "mongoPort": 27017,
        "mongoDB": "cvedb",
        "mongoUsername": "",
        "mongoPassword": "",
        "mongoSrv": False,
        "mongoAuth": "admin",
        "mongoLockMaxDurationSec": 10800,
        "DatabasePluginName": "mongodb",
        # [Download]
        "DownloadMaxWorkers": 10,
        # [dbmgt]
        "Tmpdir": "./tmp",
        # [FulltextIndex]
        "Indexdir": "./indexdir",
        # [Webserver]
        "flaskHost": "127.0.0.1",
        "flaskPort": 5000,
        "flaskDebug": True,
        "flaskSSLDebug": False,
        "pageLength": 50,
        "loginRequired": False,
        "auth_load": "./etc/auth.txt",
        "oidc": False,
        "client_id": "xx",
        "client_secret": "xx",
        "idp_discovery_url": "xx",
        "ssl_verify": False,
        "ssl": False,
        "sslCertificate": "./ssl/cve-search.crt",
        "sslKey": "./ssl/cve-search.crt",
        "WebInterface": "Full",  # defaults to Full; choices are 'Full' or 'Minimal'
        "MountPath": "/MOUNT",  # must never end with a backslash...
        # [API]
        "CVEMaxLimit": 1000,
        "CORS": False,
        "CORS_Allow_Origin": "*",
        # [Logging]
        "logging": True,
        "logfile": "./log/cve-search.log",
        "updatelogfile": "./log/update_populate.log",
        "maxLogSize": "100MB",
        "backlog": 5,
        "redisFallbackWarnings": True,
        # [Proxy]
        "http_proxy": "",
        # [CVE]
        "CVEStartYear": 2002,
    }

    sources = {
        "cwe": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "capec": "https://capec.mitre.org/data/xml/capec_latest.xml",
        "via4": "https://www.cve-search.org/feeds/via4.json",
        "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    }

    included = {
        "cpe": True,
        "cve": True,
        "cwe": True,
        "capec": True,
        "via4": True,
        "epss": True,
    }

    @classmethod
    def setCveXploreEnv(cls):
        """Wrapper for passing all the environment variables to CveXplore"""
        cls.setMongoDBEnv()
        cls.setProxyEnv()
        cls.setSourcesEnv()

    @classmethod
    def reloadConfiguration(cls):
        cls.ConfigParser.clear()
        return cls.ConfigParser.read(
            [
                os.path.join(runPath, "../etc/configuration.ini"),
                os.path.join(runPath, "../etc/sources.ini"),
            ]
        )

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

    @classmethod
    def getWebInterface(cls):
        return cls.readSetting("Webserver", "WebInterface", cls.default["WebInterface"])

    @classmethod
    def getMountPath(cls):
        return cls.readSetting("Webserver", "MountPath", cls.default["MountPath"])

    # Mongo

    @classmethod
    def getMongoHost(cls):
        return cls.readSetting("Database", "Host", cls.default["mongoHost"])

    @classmethod
    def getMongoPort(cls):
        return cls.readSetting("Database", "Port", cls.default["mongoPort"])

    @classmethod
    def getMongoDB(cls):
        """Return the database name, optionally overridden for tests."""
        db_name = cls.readSetting("Database", "DB", cls.default["mongoDB"])
        if os.getenv("USE_TEST_DB") == "1":
            db_name = f"{db_name}_test"
        return db_name

    @classmethod
    def getMongoUsername(cls):
        return cls.readSetting("Database", "Username", cls.default["mongoUsername"])

    @classmethod
    def getMongoPassword(cls):
        return cls.readSetting("Database", "Password", cls.default["mongoPassword"])

    @classmethod
    def getMongoSrvBool(cls) -> bool:
        """Returns DnsSrvRecord as a boolean, as configparser.ConfigParser() returns strings"""
        val = cls.readSetting("Database", "DnsSrvRecord", cls.default["mongoSrv"])
        return str(val).lower() in ("true", "1", "yes")

    @classmethod
    def getMongoAuthDB(cls):
        return cls.readSetting("Database", "AuthDB", cls.default["mongoAuth"])

    @classmethod
    def getMongoLockMaxDurationSec(cls) -> int:
        value = cls.readSetting(
            "Database",
            "LockMaxDurationSec",
            cls.default["mongoLockMaxDurationSec"],
        )
        try:
            return int(value)
        except (TypeError, ValueError):
            return cls.default["mongoLockMaxDurationSec"]

    @classmethod
    def getMongoPluginName(cls):
        return cls.readSetting(
            "Database", "PluginName", cls.default["DatabasePluginName"]
        )

    @classmethod
    def getMongoConnection(cls):
        # jdt_NOTE: now correctly catches exceptions due to changes in pymongo 2.9 or later
        # jdt_NOTE: https://api.mongodb.com/python/current/migrate-to-pymongo3.html#mongoclient-connects-asynchronously
        connect = pymongo.MongoClient(cls.getMongoUri(), connect=False)
        return connect[cls.getMongoDB()]

    @classmethod
    def getMongoUri(cls):
        username = urllib.parse.quote(cls.getMongoUsername())
        password = urllib.parse.quote(cls.getMongoPassword())
        host = cls.getMongoHost()
        port = cls.getMongoPort()
        db = cls.getMongoDB()
        auth_db = cls.getMongoAuthDB()

        if cls.getMongoSrvBool():
            scheme = "mongodb+srv://"
            address = f"{host}"  # no port for SRV
            cluster_params = "retryWrites=true&w=majority"
        else:
            scheme = "mongodb://"
            address = f"{host}:{port}"
            cluster_params = ""

        authentication = f"{username}:{password}@" if username and password else ""
        auth_params = f"authSource={auth_db}" if username and password else ""

        # join params safely and cleanly
        query_parts = [p for p in (auth_params, cluster_params) if p]
        query = "&".join(query_parts)
        query_str = f"?{query}" if query else ""

        return f"{scheme}{authentication}{address}/{db}{query_str}"

    @classmethod
    def setMongoDBEnv(cls):
        """Sets MongoDB settings as environment variables for CveXplore"""
        os.environ["DATASOURCE_HOST"] = cls.getMongoHost()
        os.environ["DATASOURCE_PORT"] = str(cls.getMongoPort())
        os.environ["DATASOURCE_DBNAME"] = cls.getMongoDB()

        # Pass DnsSrvRecord configuration
        if cls.getMongoSrvBool():
            os.environ["DATASOURCE_DBAPI"] = "srv"

        # Both username & password should be set to make any sense
        if cls.getMongoUsername() == "" or cls.getMongoPassword() == "":
            # Unset environment variables to make CveXplore default to None
            os.environ.pop("DATASOURCE_USER", None)
            os.environ.pop("DATASOURCE_PASSWORD", None)
        else:
            os.environ["DATASOURCE_USER"] = cls.getMongoUsername()
            os.environ["DATASOURCE_PASSWORD"] = cls.getMongoPassword()

    @classmethod
    def toPath(cls, path):
        return path if os.path.isabs(path) else os.path.join(runPath, "..", path)

    # Redis
    @classmethod
    def getRedisHost(cls):
        return cls.readSetting("Redis", "Host", cls.default["redisHost"])

    @classmethod
    def getRedisPort(cls):
        return cls.readSetting("Redis", "Port", cls.default["redisPort"])

    @classmethod
    def getRedisVendorConnection(cls):
        redisHost = cls.getRedisHost()
        redisPort = cls.getRedisPort()
        redisDB = cls.readSetting("Redis", "VendorsDB", cls.default["redisVendorDB"])
        redisPass = cls.readSetting("Redis", "Password", cls.default["redisPass"])
        return redis.StrictRedis(
            host=redisHost,
            port=redisPort,
            db=redisDB,
            password=redisPass,
            charset="utf-8",
            decode_responses=True,
        )

    @classmethod
    def getRedisNotificationsConnection(cls):
        redisHost = cls.getRedisHost()
        redisPort = cls.getRedisPort()
        redisDB = cls.readSetting(
            "Redis", "NotificationsDB", cls.default["redisNotificationsDB"]
        )
        redisPass = cls.readSetting("Redis", "Password", cls.default["redisPass"])
        return redis.StrictRedis(
            host=redisHost,
            port=redisPort,
            db=redisDB,
            password=redisPass,
            charset="utf-8",
            decode_responses=True,
        )

    # Flask
    @classmethod
    def getFlaskHost(cls):
        return cls.readSetting("Webserver", "Host", cls.default["flaskHost"])

    @classmethod
    def getFlaskPort(cls):
        return cls.readSetting("Webserver", "Port", cls.default["flaskPort"])

    @classmethod
    def getFlaskDebug(cls):
        return cls.readSetting("Webserver", "Debug", cls.default["flaskDebug"])

    @classmethod
    def getFlaskSSLDebug(cls):
        return cls.readSetting("Webserver", "SSLDebug", cls.default["flaskSSLDebug"])

    # Webserver
    @classmethod
    def getPageLength(cls):
        return cls.readSetting("Webserver", "PageLength", cls.default["pageLength"])

    # REST API
    @classmethod
    def getCVEMaxLimit(cls):
        return cls.readSetting("API", "CVEMaxLimit", cls.default["CVEMaxLimit"])

    @classmethod
    def getCORS(cls):
        return cls.readSetting("API", "CORS", cls.default["CORS"])

    @classmethod
    def getCORSAllowOrigin(cls):
        return cls.readSetting(
            "API", "CORS_Allow_Origin", cls.default["CORS_Allow_Origin"]
        )

    # Authentication
    @classmethod
    def loginRequired(cls):
        return cls.readSetting(
            "Webserver", "LoginRequired", cls.default["loginRequired"]
        )

    @classmethod
    def getAuthLoadSettings(cls):
        return cls.toPath(
            cls.readSetting("Webserver", "authSettings", cls.default["auth_load"])
        )

    @classmethod
    def useOIDC(cls):
        return cls.readSetting("Webserver", "OIDC", cls.default["oidc"])

    @classmethod
    def getClientID(cls):
        return cls.readSetting("Webserver", "CLIENT_ID", cls.default["client_id"])

    @classmethod
    def getClientSecret(cls):
        return cls.readSetting(
            "Webserver", "CLIENT_SECRET", cls.default["client_secret"]
        )

    @classmethod
    def getIDPDiscoveryUrl(cls):
        return cls.readSetting(
            "Webserver", "IDP_DISCOVERY_URL", cls.default["idp_discovery_url"]
        )

    # SSL
    @classmethod
    def useSSLVerify(cls):
        return cls.readSetting("Webserver", "SSL_VERIFY", cls.default["ssl_verify"])

    @classmethod
    def getSSLCert(cls):
        return cls.toPath(
            cls.readSetting("Webserver", "Certificate", cls.default["sslCertificate"])
        )

    @classmethod
    def getSSLKey(cls):
        return cls.toPath(cls.readSetting("Webserver", "Key", cls.default["sslKey"]))

    # Logging
    @classmethod
    def getLogfile(cls):
        return cls.toPath(cls.readSetting("Logging", "Logfile", cls.default["logfile"]))

    @classmethod
    def getUpdateLogFile(cls):
        return cls.toPath(
            cls.readSetting("Logging", "Updatelogfile", cls.default["updatelogfile"])
        )

    @classmethod
    def getLogging(cls):
        return cls.readSetting("Logging", "Logging", cls.default["logging"])

    @classmethod
    def getMaxLogSize(cls):
        size = cls.readSetting("Logging", "MaxSize", cls.default["maxLogSize"])
        split = re.findall("\\d+|\\D+", size)
        multipliers = {"KB": 1024, "MB": 1024 * 1024, "GB": 1024 * 1024 * 1024}
        if len(split) == 2:
            base = int(split[0])
            unit = split[1].strip().upper()
            return base * multipliers.get(unit, 1024 * 1024)
        # if size is not a correctly defined set it to 100MB
        else:
            return 100 * 1024 * 1024

    @classmethod
    def getBacklog(cls):
        return cls.readSetting("Logging", "Backlog", cls.default["backlog"])

    @classmethod
    def getRedisFallbackWarnings(cls):
        value = cls.readSetting(
            "Logging", "RedisFallbackWarnings", cls.default["redisFallbackWarnings"]
        )
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("true", "1", "yes", "on")
        return bool(value)

    # Download Max Workers
    @classmethod
    def getDownloadMaxWorkers(cls):
        maxWorkers = cls.readSetting(
            "Download", "MaxWorkers", cls.default["DownloadMaxWorkers"]
        )
        if type(maxWorkers) == int:
            if maxWorkers > 0:
                return maxWorkers
            else:
                return 1
        else:
            return cls.default["DownloadMaxWorkers"]

    # Indexing
    @classmethod
    def getIndexdir(cls):
        return cls.toPath(
            cls.readSetting("FulltextIndex", "Indexdir", cls.default["Indexdir"])
        )

    # Http Proxy
    @classmethod
    def getProxy(cls):
        return cls.readSetting("Proxy", "http", cls.default["http_proxy"])

    @classmethod
    def setProxyEnv(cls):
        """Sets proxy settings as environment variables for CveXplore"""
        if cls.getProxy() == "":
            # Remove environment variables
            os.environ.pop("HTTP_PROXY_DICT", None)
            os.environ.pop("HTTP_PROXY_STRING", None)
        else:
            # Set environment variables
            proxyDict = {
                "http": f"http://{cls.getProxy()}",
                "https": f"http://{cls.getProxy()}",
            }
            os.environ["HTTP_PROXY_DICT"] = json.dumps(proxyDict)
            os.environ["HTTP_PROXY_STRING"] = f"http://{cls.getProxy()}"

    @classmethod
    def getFile(cls, getfile, unpack=True):
        if cls.getProxy():
            proxy = req.ProxyHandler({"http": cls.getProxy(), "https": cls.getProxy()})
            auth = req.HTTPBasicAuthHandler()
            opener = req.build_opener(proxy, auth, req.HTTPHandler)
            req.install_opener(opener)

        response = req.urlopen(getfile)
        data = response
        # TODO: if data == text/plain; charset=utf-8, read and decode
        if unpack:
            if "gzip" in response.info().get("Content-Type"):
                buf = BytesIO(response.read())
                data = gzip.GzipFile(fileobj=buf)
            elif "bzip2" in response.info().get("Content-Type"):
                data = BytesIO(bz2.decompress(response.read()))
            elif "zip" in response.info().get("Content-Type"):
                fzip = zipfile.ZipFile(BytesIO(response.read()), "r")
                if len(fzip.namelist()) > 0:
                    data = BytesIO(fzip.read(fzip.namelist()[0]))
        return (data, response)

    # Sources
    @classmethod
    def getFeedURL(cls, source):
        return cls.readSetting("Sources", source, cls.sources.get(source, ""))

    @classmethod
    def includesFeed(cls, feed):
        return cls.readSetting("EnabledFeeds", feed, cls.included.get(feed, False))

    @classmethod
    def setSourcesEnv(cls):
        """Sets sources dictionary as an environment variable for CveXplore"""
        sources = {}
        for source in cls.sources:
            sources.update({source: cls.getFeedURL(source)})
        os.environ["SOURCES"] = json.dumps(sources)


class ConfigReader:
    def __init__(self, file):
        self.ConfigParser = configparser.ConfigParser()
        self.ConfigParser.read(file)

    def read(self, section, item, default):
        result = default
        try:
            if type(default) == bool:
                result = self.ConfigParser.getboolean(section, item)
            elif type(default) == int:
                result = self.ConfigParser.getint(section, item)
            else:
                result = self.ConfigParser.get(section, item)
        except:
            pass
        return result

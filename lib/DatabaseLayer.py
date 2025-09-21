#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Database layer translates database calls to functions
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import re
import pymongo
from datetime import datetime, timedelta, timezone

from lib.Config import Configuration as conf
from lib.cpe_conversion import split_cpe_name

from functools import lru_cache


# Lazy DB connection
@lru_cache(maxsize=1)
def _get_db():
    return conf.getMongoConnection()


# Lazy DB proxy
class LazyDB:
    def __getitem__(self, key):
        return _get_db()[key]

    def __getattr__(self, key):
        return getattr(_get_db(), key)


db = LazyDB()


# Lazy collection proxy
class LazyCollection:
    def __init__(self, name):
        self._name = name

    @property
    def collection(self):
        return _get_db()[self._name]

    def __getattr__(self, item):
        return getattr(self.collection, item)


# Initialize col* variables as lazy collections to defer DB access
colCVE = LazyCollection("cves")
colCPE = LazyCollection("cpe")
colCWE = LazyCollection("cwe")
colCPEOTHER = LazyCollection("cpeother")
colUSERS = LazyCollection("mgmt_users")
colINFO = LazyCollection("info")
colRANKING = LazyCollection("ranking")
colVIA4 = LazyCollection("via4")
colCAPEC = LazyCollection("capec")
colPlugSettings = LazyCollection("plugin_settings")
colPlugUserSettings = LazyCollection("plugin_user_settings")
colLOCKS = LazyCollection("updaterLocks")


# Functions
def sanitize(x):
    if type(x) == pymongo.cursor.Cursor:
        x = list(x)
    if type(x) == list:
        for y in x:
            sanitize(y)
    if x and "_id" in x:
        x.pop("_id")
    return x


# DB Functions
def safe_aggregate(collection, pipeline, **kwargs):
    try:
        # Use allow_disk_use by default
        return list(collection.aggregate(pipeline, allowDiskUse=True, **kwargs))
    except TypeError:
        # fallback for old MongoDB versions lacking allowDiskUse
        return list(collection.aggregate(pipeline, **kwargs))


def setColUpdate(collection, date):
    colINFO.update({"db": collection}, {"$set": {"lastModified": date}}, upsert=True)


def cpeotherBulkInsert(cpeotherlist):
    colCPEOTHER.insert(cpeotherlist)


def dropCollection(col):
    return db[col].drop()
    # jdt_NOTE: is exactly the same as drop(collection)
    # jdt_NOTE: use only one of them


def getTableNames():
    # return db.collection_names()
    # jdt_NOTE: collection_names() is depreated, list_collection_names() should be used instead
    return db.list_collection_names()


# returns True if 'target_version' is less or equal than
# 'cpe_version'
# returns False otherwise
def target_version_is_included(target_version, cpe_version):
    sp_target = target_version.split(".")
    sp_cpe = cpe_version.split(".")
    if len(sp_target) > len(sp_cpe):
        sp_cpe += [0] * (len(sp_target) - len(sp_cpe))
    if len(sp_cpe) > len(sp_target):
        sp_cpe += [0] * (len(sp_cpe) - len(sp_target))
    for i in range(len(sp_target)):
        # target version smaller than cpe version
        if int(sp_target[i]) < int(sp_cpe[i]):
            return True
        # target version greater than cpe version
        if int(sp_target[i]) > int(sp_cpe[i]):
            return False
    # target version same version as cpe version
    return True


# API Functions
def cvesForCPE(
    cpe, lax=False, vulnProdSearch=False, limit=0, strict_vendor_product=False
):
    if not cpe:
        return []

    notices = []

    cpe_regex = cpe
    final_cves = []
    cpe_searchField = (
        "vulnerable_product" if vulnProdSearch else "vulnerable_configuration"
    )

    # relaxSearch for search.py --lax; Strict search for software version is disabled.
    if lax:
        # get target version from product description provided by the user
        cpe_name = split_cpe_name(cpe)
        if len(cpe_name) != 3:
            raise ValueError(
                f"Format 'vendor:product:version' expected in --lax mode, got '{cpe}'"
            )
        target_version = cpe_name[-1]
        product = ":".join(cpe_name[:-1])

        # For easier version comparison of exceptional version strings (not simple 1.2.3), simplify
        # version strings containing non-numeric characters like "1.1.3p2" or "1.1.3mr2" as "1.1.3.0.2";
        # the extra zero (.0.) is for avoiding collisions between, e.g., "1.0p1" and "1.0.1",
        # where 1.0p1, converted to 1.0.0.1, will be less than 1.0.1.
        target_version_simplified = re.sub(r"[^\d\.]+", ".0.", target_version)
        # ...and then remove duplicate, leading & tailing dots
        target_version_simplified = re.sub(r"[\.]+", ".", target_version_simplified)
        target_version_simplified = target_version_simplified.strip(".")

        # Notify user of the simplification.
        if target_version_simplified != target_version:
            notices.append(
                f"Notice: Target version {target_version} simplified as {target_version_simplified} for "
                f"easier version comparison; doing the same for CPEs in Vulnerable Configs under the hood."
            )

        # over-approximate versions
        cpe_regex = product

        pipeline = [
            {"$match": {cpe_searchField: {"$regex": cpe_regex}}},
            {"$sort": {"modified": -1, "cvss": -1} if limit != 0 else {"modified": -1}},
        ]
        if limit != 0:
            pipeline.append({"$limit": limit})
        cves = safe_aggregate(colCVE, pipeline)

        i = 0

        for cve in cves:
            vuln_confs = cve["vulnerable_configuration"]
            vuln_confs += cve["vulnerable_configuration_cpe_2_2"]
            vuln_confs += cve["vulnerable_product"]
            i += 1
            for vc in vuln_confs:
                if cpe_regex not in vc:
                    continue

                re_from_start = re.compile("^.*{}:".format(re.escape(cpe_regex)))
                cpe_version = re_from_start.sub("", vc)
                cpe_version = split_cpe_name(cpe_version)[0]

                # Simplify equally with the target_version to enable comparison
                cpe_version_simplified = re.sub(r"[^\d\.]+", ".0.", cpe_version)
                cpe_version_simplified = re.sub(r"[\.]+", ".", cpe_version_simplified)
                cpe_version_simplified = cpe_version_simplified.strip(".")

                if len(cpe_version_simplified) == 0:
                    continue
                if target_version_is_included(
                    target_version_simplified, cpe_version_simplified
                ):
                    final_cves.append(cve)
                    break

    elif strict_vendor_product:
        # strict product search

        vendor, product = cpe

        cpe_regex_string = r"^{}".format(re.escape(product))

        pipeline = [
            {"$match": {"vendors": vendor, "products": {"$regex": cpe_regex_string}}}
        ]
        if limit != 0:
            pipeline.append({"$sort": {"cvss": -1}})
            pipeline.append({"$limit": limit})
        final_cves = safe_aggregate(colCVE, pipeline)

    else:
        # create strict cpe regex

        if cpe_regex.startswith("cpe"):
            # strict search with term starting with cpe; e.g: cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:*:*

            remove_trailing_regex_stars = r"(?:\:|\:\:|\:\*)+$"

            cpe_regex = re.escape(re.sub(remove_trailing_regex_stars, "", cpe_regex))

            cpe_regex_string = r"^{}:".format(cpe_regex)
        else:
            # more general search on same field; e.g. microsoft:windows_7
            cpe_regex_string = "{}".format(re.escape(cpe_regex))

        # default strict search
        pipeline = [
            {"$match": {cpe_searchField: {"$regex": cpe_regex_string}}},
            {"$sort": {"cvss": -1}},
        ]
        if limit != 0:
            pipeline.append({"$limit": limit})
        final_cves = safe_aggregate(colCVE, pipeline)

    final_cves = sanitize(final_cves)
    if not notices:
        return {"results": final_cves, "total": len(final_cves)}
    else:
        return {"notices": notices, "results": final_cves, "total": len(final_cves)}


# Query Functions
# Generic data
def getCVEs(limit=False, query=None, skip=0, cves=None, collection=None):
    col = colCVE if collection is None else db[collection]

    # Normalize query
    if query is None:
        query = []
    elif isinstance(query, dict):
        query = [query]

    # Filter by specific CVE IDs if provided
    if isinstance(cves, list) and cves:
        query.append({"id": {"$in": cves}})

    # Build aggregation pipeline
    pipeline = []

    if not query:
        pipeline.append({"$match": {}})
    elif len(query) == 1:
        pipeline.append({"$match": query[0]})
    else:
        pipeline.append({"$match": {"$and": query}})

    pipeline.append({"$sort": {"modified": -1}})

    if limit:
        pipeline.append({"$limit": limit})
    if skip:
        pipeline.append({"$skip": skip})

    cve_cursor = safe_aggregate(col, pipeline)
    cve = list(cve_cursor)

    return {"results": sanitize(cve), "total": len(cve)}


def getCVEsNewerThan(dt):
    return getCVEs(query={"lastModified": {"$gt": dt}})


def getCVEIDs(limit=0):
    pipeline = [
        {"$sort": {"modified": -1}},  # -1 is equivalent to pymongo.DESCENDING
    ]
    if limit > 0:
        pipeline.append({"$limit": limit})
    results = safe_aggregate(colCVE, pipeline)
    return [x["id"] for x in results]


def searchCVE(find_params=None, limit=0):
    pipeline = [
        {"$match": {} if find_params is None else find_params},
        {"$sort": {"modified": -1}},  # -1 is equivalent to pymongo.DESCENDING
    ]
    if limit > 0:
        pipeline.append({"$limit": limit})
    return safe_aggregate(colCVE, pipeline)


def getCVE(id, collection=None):
    col = colCVE if not collection else db[collection]
    return sanitize(col.find_one({"id": id}))


def getCPE(id):
    return sanitize(colCPE.find_one({"id": id}))


def getCPEs():
    return sanitize(colCPE.find())


def getAlternativeCPE(id):
    return sanitize(colCPEOTHER.find_one({"id": id}))


def getAlternativeCPEs():
    return sanitize(colCPEOTHER.find())


def getVIA4(id):
    return sanitize(colVIA4.find_one({"id": id}))


def getCPEMatching(regex, fullSearch=False):
    lst = list(colCPE.find({"title": {"$regex": regex}}))
    if fullSearch:
        lst.extend(colCPEOTHER.find({"title": {"$regex": regex}}))
    return lst


def getFreeText(text):
    try:  # Before Mongo 3
        return [x["obj"] for x in db.command("text", "cves", search=text)["results"]]
    except:  # As of Mongo 3
        return sanitize(colCVE.find({"$text": {"$search": text}}))


def getSearchResults(search):
    result = {"data": []}
    regSearch = re.compile(re.escape(search), re.IGNORECASE)
    links = {"n": "Link", "d": []}
    via4 = getInfo("via4")
    if via4:
        for vLink in via4.get("searchables", []):
            links["d"].extend(sanitize(colVIA4.find({vLink: {"$in": [regSearch]}})))

    try:
        textsearch = {"n": "Text search", "d": getFreeText(search)}
    except:
        textsearch = {"n": "Text search", "d": []}
        result["errors"] = ["textsearch"]

    search = search.lower()

    vendor_query = {
        "n": "Vendor",
        "d": getCVEs(query=[{"vendors": search.replace(" ", "")}])["results"],
    }
    product_query = {
        "n": "Product",
        "d": getCVEs(query=[{"products": search.replace(" ", "_")}])["results"],
    }

    for collection in [vendor_query, product_query, links, textsearch]:
        for item in collection["d"]:
            # Check if already in result data
            if not any(item["id"] == entry["id"] for entry in result["data"]):
                entry = getCVE(item["id"])
                if entry:
                    entry["reason"] = collection["n"]
                    result["data"].append(entry)
    return result


def getCAPECFor(capecid):
    return sanitize(colCAPEC.find({"related_weakness": {"$in": [capecid]}}))


def getCAPEC(capecid):
    return sanitize(colCAPEC.find_one({"id": capecid}))


def getCWEs(cweid=None):
    if cweid is None:
        return sanitize(sorted(colCWE.find(), key=lambda k: int(k["id"])))
    else:
        return sanitize(colCWE.find_one({"id": cweid}))


def getInfo(collection):
    return sanitize(colINFO.find_one({"db": collection}))


def getLastModified(collection):
    info = getInfo(collection)
    return info["lastModified"] if info else None


def getSize(collection):
    return db[collection].count_documents(filter={})


def via4Linked(key, val):
    cveList = [x["id"] for x in colVIA4.find({key: val})]
    return sanitize(getCVEs(query={"id": {"$in": cveList}}))


def getDBStats(include_admin=False):
    data = {"cves": {}, "cpe": {}, "cpeother": {}, "capec": {}, "cwe": {}, "via4": {}}
    for key in data.keys():
        data[key] = {
            "size": getSize(key.lower()),
            "last_update": getLastModified(key.lower()),
        }
    if include_admin:
        data = {
            "stats": {
                "size_on_disk": db.command("dbstats")["storageSize"],
                "db_size": db.command("dbstats")["dataSize"],
                "name": conf.getMongoDB(),
            },
            "data": data,
        }
    return data


# Dynamic data
def addRanking(cpe, key, rank):
    item = findRanking(cpe)
    if item is None:
        colRANKING.update_one(
            {"cpe": cpe}, {"$push": {"rank": {key: rank}}}, upsert=True
        )
    else:
        l = []
        for i in item["rank"]:
            i[key] = rank
            l.append(i)
        colRANKING.update_one({"cpe": cpe}, {"$set": {"rank": l}})
    return True


def removeRanking(cpe):
    return sanitize(colRANKING.delete_one({"cpe": {"$regex": cpe, "$options": "i"}}))


def findRanking(cpe=None, regex=False):
    if not cpe:
        return sanitize(colRANKING.find())
    if regex:
        safe_cpe = re.escape(cpe)  # escape all regex meta characters
        return sanitize(colRANKING.find_one({"cpe": {"$regex": safe_cpe}}))
    else:
        return sanitize(colRANKING.find_one({"cpe": cpe}))


# Per-source locking helpers.
# Used to ensure that only one updater runs for a given source at a time.


def acquire_lock(source: str, collection=colLOCKS) -> bool:
    """
    Acquire a per-source lock. Treat locks older than the configured
    max duration as stale and remove them before acquiring.
    """
    now = datetime.now(timezone.utc)
    max_duration = conf.getMongoLockMaxDurationSec()

    # Remove stale lock if max_duration > 0
    if max_duration > 0:
        expire_time = now - timedelta(seconds=max_duration)
        collection.delete_one({"_id": source, "started_at": {"$lt": expire_time}})

    res = collection.find_one_and_update(
        {"_id": source},
        {"$setOnInsert": {"started_at": datetime.utcnow()}},
        upsert=True,
        return_document=pymongo.ReturnDocument.BEFORE,
    )
    return res is None


def release_lock(source: str, collection=colLOCKS) -> None:
    collection.delete_one({"_id": source})


def any_lock_active(collection=colLOCKS) -> bool:
    """
    Return True if any non-stale lock is active.
    Stale locks are automatically removed before checking.
    """
    now = datetime.now(timezone.utc)
    max_duration = conf.getMongoLockMaxDurationSec()

    if max_duration > 0:
        expire_time = now - timedelta(seconds=max_duration)
        collection.delete_many({"started_at": {"$lt": expire_time}})
    return collection.count_documents({}) > 0

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Database layer translates database calls to functions
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import ast
import re
import sys

import pymongo

from lib.Config import Configuration as conf

# Variables
db = conf.getMongoConnection()
colCVE = db["cves"]
colCPE = db["cpe"]
colCWE = db["cwe"]
colCPEOTHER = db["cpeother"]
colWHITELIST = db["mgmt_whitelist"]
colBLACKLIST = db["mgmt_blacklist"]
colUSERS = db["mgmt_users"]
colINFO = db["info"]
colRANKING = db["ranking"]
colVIA4 = db["via4"]
colCAPEC = db["capec"]
colPlugSettings = db["plugin_settings"]
colPlugUserSettings = db["plugin_user_settings"]

mongo_version = db.command("buildinfo")["versionArray"]
# to check if mongodb > 4.4
# if it is, then use allow_disk_use for optimized queries
# to be removed in future with the conditional statements
# and use allow_disk_use by default

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
def ensureIndex(collection, field, **kwargs):
    db[collection].create_index(field, **kwargs)


def drop(collection):
    db[collection].drop()


def setColUpdate(collection, date):
    colINFO.update({"db": collection}, {"$set": {"last-modified": date}}, upsert=True)


def setColInfo(collection, field, data):
    colINFO.update({"db": collection}, {"$set": {field: data}}, upsert=True)


def insertCVE(cve):
    colCVE.insert(cve)


def updateCVE(cve):
    if cve["cvss3"] is not None:
        colCVE.update(
            {"id": cve["id"]},
            {
                "$set": {
                    "cvss3": cve["cvss3"],
                    "impact3": cve["impact3"],
                    "exploitability3": cve["exploitability3"],
                    "cvss3-vector": cve["cvss3-vector"],
                    "impactScore3": cve["impactScore3"],
                    "exploitabilityScore3": cve["exploitabilityScore3"],
                    "cvss": cve["cvss"],
                    "summary": cve["summary"],
                    "references": cve["references"],
                    "impact": cve["impact"],
                    "vulnerable_product": cve["vulnerable_product"],
                    "access": cve["access"],
                    "cwe": cve["cwe"],
                    "vulnerable_configuration": cve["vulnerable_configuration"],
                    "vulnerable_configuration_cpe_2_2": cve[
                        "vulnerable_configuration_cpe_2_2"
                    ],
                    "last-modified": cve["Modified"],
                }
            },
            upsert=True,
        )
    else:
        colCVE.update(
            {"id": cve["id"]},
            {
                "$set": {
                    "cvss3": cve["cvss3"],
                    "cvss": cve["cvss"],
                    "summary": cve["summary"],
                    "references": cve["references"],
                    "impact": cve["impact"],
                    "vulnerable_product": cve["vulnerable_product"],
                    "access": cve["access"],
                    "cwe": cve["cwe"],
                    "vulnerable_configuration": cve["vulnerable_configuration"],
                    "vulnerable_configuration_cpe_2_2": cve[
                        "vulnerable_configuration_cpe_2_2"
                    ],
                    "last-modified": cve["Modified"],
                }
            },
            upsert=True,
        )


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
def cvesForCPE(cpe, lax=False, vulnProdSearch=False, limit=0, strict_vendor_product=False):
    if not cpe:
        return []

    cpe_regex = cpe
    final_cves = []
    cpe_searchField = (
        "vulnerable_product" if vulnProdSearch else "vulnerable_configuration"
    )

    if lax:
        # get target version from product description provided by the user
        target_version = cpe.split(":")[-1]
        product = cpe.rsplit(":", 1)[0]
        # perform checks on the target version
        if None is target_version or [] is target_version:
            print(
                "Error, target version not found at the end of product description '{}'".format(
                    cpe
                )
            )
            sys.exit(-1)
        for i in target_version.split("."):
            try:
                int(i)
            except:
                print(
                    "Error, target version should be of the form '1.2.3'. Current form is '{}'".format(
                        target_version
                    )
                )
                sys.exit(-1)

        # over-approximate versions
        cpe_regex = product

        if limit != 0:
            if mongo_version > [4, 4]:
                cves = (
                    colCVE.find({cpe_searchField: {"$regex": cpe_regex}})
                    .limit(limit)
                    .sort(
                        [("Modified", pymongo.DESCENDING), ("cvss", pymongo.DESCENDING)]
                    )
                    .allow_disk_use(True)
                )
            else:
                cves = (
                    colCVE.find({cpe_searchField: {"$regex": cpe_regex}})
                    .limit(limit)
                    .sort(
                        [("Modified", pymongo.DESCENDING), ("cvss", pymongo.DESCENDING)]
                    )
                )
        else:
            if mongo_version > [4, 4]:
                cves = (
                    colCVE.find({cpe_searchField: {"$regex": cpe_regex}})
                    .sort("Modified", direction=pymongo.DESCENDING)
                    .allow_disk_use(True)
                )
            else:
                cves = colCVE.find({cpe_searchField: {"$regex": cpe_regex}}).sort(
                    "Modified", direction=pymongo.DESCENDING
                )

        i = 0

        for cve in cves:
            vuln_confs = cve["vulnerable_configuration"]
            vuln_confs += cve["vulnerable_configuration_cpe_2_2"]
            vuln_confs += cve["vulnerable_product"]
            i += 1
            for vc in vuln_confs:
                if cpe_regex not in vc:
                    continue

                re_from_start = re.compile("^.*{}:".format(cpe_regex))
                cpe_version = re_from_start.sub("", vc)

                # TODO: handle versions such as "1.1.3:p2"
                cpe_version = cpe_version.split(":")[0]

                # TODO: handle versions such as "1.1.3p2"
                cpe_version = re.search(r"([0-9\.]*)", cpe_version).group(0)
                if len(cpe_version) == 0:
                    # TODO: print warnings
                    # print ("Warning, missing cpe version for {}: '{}'. Skipping cpe.".format(cve["id"], vc))
                    continue
                if target_version_is_included(target_version, cpe_version):
                    final_cves.append(cve)
                    break
    elif strict_vendor_product:
        # strict product search

        vendor, product = cpe

        cpe_regex_string = r"^{}".format(re.escape(product))

        if limit != 0:
            if mongo_version > [4, 4]:
                cves = (
                    colCVE.find({"vendors": vendor, "products": {"$regex": cpe_regex_string}})
                    .limit(limit)
                    .sort("cvss", direction=pymongo.DESCENDING)
                    .allow_disk_use(True)
                )
            else:
                cves = (
                    colCVE.find({"vendors": vendor, "products": {"$regex": cpe_regex_string}})
                    .limit(limit)
                    .sort("cvss", direction=pymongo.DESCENDING)
                )
        else:
            cves = colCVE.find({"vendors": vendor, "products": {"$regex": cpe_regex_string}})

        final_cves = cves

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
        if limit != 0:
            if mongo_version > [4, 4]:
                cves = (
                    colCVE.find({"{}".format(cpe_searchField): {"$regex": cpe_regex_string}})
                    .limit(limit)
                    .sort("cvss", direction=pymongo.DESCENDING)
                    .allow_disk_use(True)
                )
            else:
                cves = (
                    colCVE.find({"{}".format(cpe_searchField): {"$regex": cpe_regex_string}})
                    .limit(limit)
                    .sort("cvss", direction=pymongo.DESCENDING)
                )
        else:
            cves = colCVE.find({"{}".format(cpe_searchField): {"$regex": cpe_regex_string}})

        final_cves = cves

    final_cves = sanitize(final_cves)
    return {"results": final_cves, "total": len(final_cves)}


# Query Functions
# Generic data
def getCVEs(limit=False, query=[], skip=0, cves=None, collection=None):
    col = colCVE if not collection else db[collection]
    if type(query) == dict:
        query = [query]
    if type(cves) == list:
        query.append({"id": {"$in": cves}})
    if len(query) == 0:
        if mongo_version > [4, 4]:
            cve = (
                col.find()
                .sort("Modified", pymongo.DESCENDING)
                .limit(limit)
                .skip(skip)
                .allow_disk_use(True)
            )
        else:
            cve = (
                col.find().sort("Modified", pymongo.DESCENDING).limit(limit).skip(skip)
            )
    elif len(query) == 1:
        if mongo_version > [4, 4]:
            cve = (
                col.find(query[0])
                .sort("Modified", pymongo.DESCENDING)
                .limit(limit)
                .skip(skip)
                .allow_disk_use(True)
            )
        else:
            cve = (
                col.find(query[0])
                .sort("Modified", pymongo.DESCENDING)
                .limit(limit)
                .skip(skip)
            )
    else:
        if mongo_version > [4, 4]:
            cve = (
                col.find({"$and": query})
                .sort("Modified", pymongo.DESCENDING)
                .limit(limit)
                .skip(skip)
                .allow_disk_use(True)
            )
        else:
            cve = (
                col.find({"$and": query})
                .sort("Modified", pymongo.DESCENDING)
                .limit(limit)
                .skip(skip)
            )

    return {"results": sanitize(cve), "total": cve.count()}


def getCVEsNewerThan(dt):
    return getCVEs(query={"last-modified": {"$gt": dt}})


def getCVEIDs(limit=-1):
    if mongo_version > [4, 4]:
        return [
            x["id"]
            for x in colCVE.find()
            .limit(limit)
            .sort("Modified", pymongo.DESCENDING)
            .allow_disk_use(True)
        ]
    else:
        return [
            x["id"]
            for x in colCVE.find().limit(limit).sort("Modified", pymongo.DESCENDING)
        ]


def getCVE(id, collection=None):
    col = colCVE if not collection else db[collection]
    return sanitize(col.find_one({"id": id}))


def getCPE(id):
    return sanitize(colCPE.find_one({"id": id}))


def getCPEVersionInformation(query):
    return sanitize(colCPE.find_one(query))


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

    for collection in [links, textsearch]:
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
    return info["last-modified"] if info else None


def getSize(collection):
    return db[collection].count()


def via4Linked(key, val):
    cveList = [x["id"] for x in colVIA4.find({key: val})]
    return sanitize(getCVEs(query={"id": {"$in": cveList}}))


def getDBStats(include_admin=False):
    data = {"cves": {}, "cpe": {}, "cpeOther": {}, "capec": {}, "cwe": {}, "via4": {}}
    for key in data.keys():
        data[key] = {
            "size": getSize(key.lower()),
            "last_update": getLastModified(key.lower()),
        }
    if include_admin:
        data["whitelist"] = {"size": colWHITELIST.count()}
        data["blacklist"] = {"size": colBLACKLIST.count()}
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
def getWhitelist():
    return sanitize(colWHITELIST.find())


def isInWhitelist(cpe):
    return True if colWHITELIST.find({"id": cpe}).count() > 0 else False


def addToWhitelist(cpe, type, comments=None):
    if comments:
        colWHITELIST.insert({"id": cpe, "type": type, "comments": comments})
    else:
        colWHITELIST.insert({"id": cpe, "type": type})


def removeFromWhitelist(cpe):
    colWHITELIST.remove({"id": cpe})


def updateWhitelist(oldCPE, newCPE, type, comments=None):
    if comments:
        colWHITELIST.update(
            {"id": oldCPE}, {"id": newCPE, "type": type, "comments": comments}
        )
    else:
        colWHITELIST.update({"id": oldCPE}, {"id": newCPE, "type": type})


def getBlacklist():
    return sanitize(colBLACKLIST.find())


def isInBlacklist(cpe):
    return True if colBLACKLIST.find({"id": cpe}).count() > 0 else False


def addToBlacklist(cpe, type, comments=None):
    if comments:
        colBLACKLIST.insert({"id": cpe, "type": type, "comments": comments})
    else:
        colBLACKLIST.insert({"id": cpe, "type": type})


def removeFromBlacklist(cpe):
    colBLACKLIST.remove({"id": cpe})


def updateBlacklist(oldCPE, newCPE, type, comments=None):
    if comments:
        colBLACKLIST.update(
            {"id": oldCPE}, {"id": newCPE, "type": type, "comments": comments}
        )
    else:
        colBLACKLIST.update({"id": oldCPE}, {"id": newCPE, "type": type})


def getRules(list):
    if list.lower() == "whitelist":
        col = colWHITELIST
    elif list.lower() == "blacklist":
        col = colBLACKLIST
    else:
        return []
    rlist = col.find({"type": "cpe"}).distinct("id")
    rlist.extend(
        [
            "cpe:2.3:([^:]*:){9}" + re.escape(x)
            for x in col.find({"type": "targethardware"}).distinct("id")
        ]
    )
    rlist.extend(
        [
            "cpe:2.3:([^:]*:){8}" + re.escape(x)
            for x in col.find({"type": "targetsoftware"}).distinct("id")
        ]
    )
    return rlist


def addRanking(cpe, key, rank):
    item = findRanking(cpe)
    if item is None:
        colRANKING.update({"cpe": cpe}, {"$push": {"rank": {key: rank}}}, upsert=True)
    else:
        l = []
        for i in item["rank"]:
            i[key] = rank
            l.append(i)
        colRANKING.update({"cpe": cpe}, {"$set": {"rank": l}})
    return True


def removeRanking(cpe):
    return sanitize(colRANKING.remove({"cpe": {"$regex": cpe, "$options": "i"}}))


def findRanking(cpe=None, regex=False):
    if not cpe:
        # return sanitize(colRANKING.find())
        return None
    if regex:
        # return sanitize(colRANKING.find_one({'cpe': {'$regex': cpe}}))
        return None
    else:
        return None
        # return sanitize(colRANKING.find_one({'cpe': cpe}))


###########
# Plugins #
###########
# Settings
def p_writeSetting(plugin, setting, value):
    colPlugSettings.update({"plugin": plugin}, {"$set": {setting: value}}, upsert=True)


def p_readSetting(plugin, setting):
    data = list(
        colPlugSettings.find({"plugin": plugin}, {setting: 1}).distinct(setting)
    )
    if len(data) != 0:
        data = data[0]
        return data
    return None


def p_deleteSettings(plugin):
    colPlugSettings.remove({"plugin": plugin})


def p_writeUserSetting(plugin, user, setting, value):
    colPlugUserSettings.update(
        {"plugin": plugin, "user": user}, {"$set": {setting: value}}, upsert=True
    )


def p_readUserSetting(plugin, user, setting):
    data = list(
        colPlugUserSettings.find(
            {"plugin": plugin, "user": user}, {setting: 1}
        ).distinct(setting)
    )
    if len(data) != 0:
        data = data[0]
        return data
    return None


def p_deleteUserSettings(plugin):
    colPlugUserSettings.remove({"plugin": plugin})


# Query
def p_queryData(collection, query):
    return sanitize(db["plug_%s" % collection].find(query))


def p_queryOne(collection, query):
    data = sanitize(db["plug_%s" % collection].find_one(query))
    return data if data else []  # Compatibility between several Flask-PyMongo versions


# Data manipulation
def p_drop(col):
    db["plug_%s" % col].drop()


def p_addEntry(collection, data):
    db["plug_%s" % collection].insert(data)


def p_removeEntry(collection, query):
    db["plug_%s" % collection].remove(query)


def p_bulkUpdate(collection, keyword, data):
    if type(data) is not list:
        data = [data]
    if len(data) > 0:
        bulk = db["plug_%s" % collection].initialize_ordered_bulk_op()
        for x in data:
            bulk.find({keyword: x[keyword]}).upsert().update({"$set": x})
        bulk.execute()


def p_addToList(collection, query, listname, data):
    if type(data) != list:
        data = [data]
    current = list(p_queryData(collection, query))
    if len(current) == 0:
        p_addEntry(collection, query)
    for entry in current:
        if listname in entry:
            data = list(
                set([repr(x) for x in data]) - set([repr(x) for x in entry[listname]])
            )
            data = [ast.literal_eval(x) for x in data]
        if data:
            db["plug_%s" % collection].update(
                query, {"$addToSet": {listname: {"$each": data}}}
            )


def p_removeFromList(collection, query, listname, data):
    if type(data) == dict:
        db["plug_%s" % collection].update(query, {"$pull": {listname: data}})
    elif type(data) != list:
        data = [data]
    db["plug_%s" % collection].update(query, {"$pullAll": {listname: data}})

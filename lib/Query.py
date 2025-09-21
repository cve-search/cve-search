#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Query tools
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2014-2018  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import os
import sys
import logging

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from redis.exceptions import ConnectionError, TimeoutError, RedisError

from lib.Toolkit import toStringFormattedCPE
from lib.CVEs import CveHandler
from lib.Config import Configuration
from lib.cpe_conversion import split_cpe_name
from lib.DatabaseHandler import DatabaseHandler

logger = logging.getLogger(__name__)
rankinglookup = True

SCAN_COUNT = 1000

redisdb = Configuration.getRedisVendorConnection()


def get_redis_connection():
    global redisdb
    try:
        redisdb.ping()  # quick test to see if connection is alive
    except (ConnectionError, TimeoutError, RedisError):
        # reconnect if the existing connection failed
        redisdb = Configuration.getRedisVendorConnection()
    return redisdb


def redis_or_mongo(redis_func, mongo_func, context="", *args, **kwargs):
    # Try Redis first, fallback to MongoDB if needed, with logging context.
    mongoFallback = False
    try:
        redis_conn = get_redis_connection()
        result = redis_func(redis_conn, *args, **kwargs)

        # Detect empty / fallback cases
        if not result:
            mongoFallback = True
        elif isinstance(result, tuple) and all(r is None for r in result):
            mongoFallback = True

        if mongoFallback and Configuration.getRedisFallbackWarnings():
            logger.warning(f"Redis empty when {context}. Falling back to MongoDB.")

    except (ConnectionError, TimeoutError, RedisError) as e:
        mongoFallback = True
        if Configuration.getRedisFallbackWarnings():
            logger.warning(f"Redis error when {context}: {e}. Falling back to MongoDB.")

    if mongoFallback:
        dbh = DatabaseHandler()
        result = mongo_func(dbh, *args, **kwargs)

    return result


def findranking(cpe=None, loosy=True):
    from lib.DatabaseLayer import findRanking

    i = None

    if cpe is None:
        return False

    result = False

    if loosy:
        for x in split_cpe_name(cpe):
            if x != "":
                i = findRanking(cpe, regex=True)
            if i is None:
                continue
            if "rank" in i:
                result = i["rank"]
    else:
        i = findRanking(cpe, regex=True)
        print(cpe)
        if i is None:
            return result
        if "rank" in i:
            result = i["rank"]
    return result


def lookupcpe(cpeid=None):
    from lib.DatabaseLayer import getCPE

    e = getCPE(cpeid)
    if e is None:
        return cpeid
    if "id" in e:
        return e["title"]


# Lastly added
def qcvesForCPE(cpe, limit=0):
    from lib.DatabaseLayer import cvesForCPE

    cpe = toStringFormattedCPE(cpe)
    data = []
    if cpe:
        cvesp = CveHandler(
            rankinglookup=False, namelookup=False, via4lookup=True, capeclookup=False
        )
        r = cvesForCPE(cpe, limit=limit)
        for x in r["results"]:
            data.append(cvesp.getcve(x["id"]))
    return data


def getBrowseList(vendor):
    def redis_func(redis_conn, vendor):
        if (vendor is None) or isinstance(vendor, list):
            # fetch all vendors from Redis sets
            v1 = redis_conn.smembers("o")
            v2 = redis_conn.smembers("a")
            v3 = redis_conn.smembers("h")
            if v1 or v2 or v3:
                return sorted(list(set(list(v1) + list(v2) + list(v3)))), None
            return None, None  # trigger fallback
        else:
            # fetch products for a specific vendor
            cpenum = redis_conn.scard("v:" + vendor)
            if cpenum < 1:
                return None, None  # trigger fallback
            p = redis_conn.smembers("v:" + vendor)
            return vendor, sorted(list(p))

    def mongo_func(dbh, vendor):
        if (vendor is None) or isinstance(vendor, list):
            vendor_list = sorted(
                filter(None, dbh.connection.store_cves.distinct("vendors"))
            )
            return vendor_list, None
        else:
            products = sorted(
                filter(
                    None,
                    dbh.connection.store_cves.distinct("products", {"vendors": vendor}),
                )
            )
            return vendor, products

    context = (
        "fetching vendor list"
        if (vendor is None) or isinstance(vendor, list)
        else f'fetching products for vendor "{vendor}"'
    )
    vendor_res, cpe_res = redis_or_mongo(
        redis_func, mongo_func, context=context, vendor=vendor
    )
    return {"vendor": vendor_res, "product": cpe_res}


def getVersionsOfProduct(product):
    def redis_func(redis_conn, product):
        p = redis_conn.smembers("p:" + product)
        return sorted(list(p))

    def mongo_func(dbh, product):
        docs = dbh.connection.store_cpe.find(
            {"product": product},
            {"cpeName": 1, "stem": 1, "_id": 0},
        )
        versions = [
            # Match Redis output format by stripping the "stem:" prefix
            # (e.g., remove "cpe:2.3:a:vendor:product:" from cpeName)
            doc["cpeName"][len(doc["stem"]) + 1 :]
            for doc in docs
            if "cpeName" in doc
        ]
        return sorted(versions)

    context = f"fetching versions for product {product}"
    return redis_or_mongo(redis_func, mongo_func, context=context, product=product)


def searchVendors(vendor_part):
    def redis_func(redis_conn, vendor_part):
        vendors = [
            vendor.replace("v:", "")
            for vendor in redis_conn.scan_iter(f"v:*{vendor_part}*", count=SCAN_COUNT)
        ]
        return vendors

    def mongo_func(dbh, vendor_part):
        return dbh.connection.store_cpe.distinct(
            "vendor", {"vendor": {"$regex": vendor_part, "$options": "i"}}
        )

    context = f"searching vendors with part '{vendor_part}'"
    vendors = redis_or_mongo(
        redis_func, mongo_func, context=context, vendor_part=vendor_part
    )
    return {"vendor": sorted(vendors)}


def searchProductsByVendor(vendor, product_part):
    def redis_func(redis_conn, vendor, product_part):
        product_iterator = redis_conn.sscan_iter(
            f"v:{vendor}", f"*{product_part}*", count=SCAN_COUNT
        )
        products = [product.replace("p:", "") for product in product_iterator]
        return sorted(products)

    def mongo_func(dbh, vendor, product_part):
        return sorted(
            dbh.connection.store_cpe.distinct(
                "product",
                {
                    "vendor": vendor,
                    "product": {"$regex": product_part, "$options": "i"},
                },
            )
        )

    context = f'searching products for vendor "{vendor}" with part "{product_part}"'
    products = redis_or_mongo(redis_func, mongo_func, context, vendor, product_part)
    return {"product": products, "vendor": vendor}


def searchVersionsByProduct(vendor, product, version_part):
    def redis_func(redis_conn, vendor, product, version_part):
        version_iterator = redis_conn.sscan_iter(
            f"p:{product}", f"*{version_part}*", count=SCAN_COUNT
        )
        versions = list(version_iterator)
        return versions

    def mongo_func(dbh, vendor, product, version_part):
        docs = dbh.connection.store_cpe.find(
            {
                "vendor": vendor,
                "product": product,
                "version": {"$regex": version_part, "$options": "i"},
            },
            {"cpeName": 1, "stem": 1, "_id": 0},
        )
        return sorted(
            # Match Redis output format by stripping the "stem:" prefix
            # (e.g., remove "cpe:2.3:a:vendor:product:" from cpeName)
            doc["cpeName"][len(doc["stem"]) + 1 :]
            for doc in docs
            if "cpeName" in doc
        )

    context = f"searching versions for vendor '{vendor}', product '{product}' with part '{version_part}'"
    versions = redis_or_mongo(
        redis_func, mongo_func, context, vendor, product, version_part
    )
    return {"version": sorted(versions), "product": product, "vendor": vendor}

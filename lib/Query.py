#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Query tools
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import urllib.parse
import json
import requests

from lib.Config import Configuration


db = Configuration.getMongoConnection()
collection = db.cves

rankinglookup = True


def findranking(cpe=None, loosy=True):
  if cpe is None:
    return False
  r = db.ranking
  result = False
  if loosy:
    for x in cpe.split(':'):
      if x is not '':
        i = r.find_one({'cpe': {'$regex': x}})
      if i is None:
        continue
      if 'rank' in i:
        result = i['rank']
  else:
    i = r.find_one({'cpe': {'$regex': cpe}})
    print (cpe)
    if i is None:
      return result
    if 'rank' in i:
      result = i['rank']
  return result

def lookupcpe(cpeid=None):
    e = db.cpe.find_one({'id': cpeid})
    if e is None:
        return cpeid
    if 'id' in e:
        return e['title']


def lastentries(limit=5, namelookup=False):
  entries = []
  for item in collection.find({}).sort("Modified", -1).limit(limit):
    if not namelookup and rankinglookup is not True:
      entries.append(item)
    else:
      if "vulnerable_configuration" in item:
        vulconf = []
        ranking = []
        for conf in item['vulnerable_configuration']:
          if namelookup:
            vulconf.append(lookupcpe(cpeid=conf))
          else:
            vulconf.append(conf)
          if rankinglookup:
            rank = findranking(cpe=conf)
            if rank and rank not in ranking:
              ranking.append(rank)
        item['vulnerable_configuration'] = vulconf
        if rankinglookup:
          item['ranking'] = ranking
      entries.append(item)
  return entries

def apigetcve(api, cveid=None):
  if cveid is None:
    return False
  url = urllib.parse.urljoin(api, "api/cve/"+cveid)
  urltoget = urllib.parse.urljoin(url, cveid)
  r = requests.get(urltoget)
  if r.status_code is 200:
    return r.text
  else:
    return False

def apibrowse(api, vendor=None):
  url = urllib.parse.urljoin(api, "api/browse")
  if vendor is None:
    r = requests.get(url)
  else:
    urlvendor = url + "/" + vendor
    r = requests.get(urlvendor)

  if r.status_code is 200:
    return r.text
  else:
    return False

def apisearch(api, query=None):
  if query is None:
    return False
  url = urllib.parse.urljoin(api, "api/search/")
  url = url+query

  r = requests.get(url)
  if r.status_code is 200:
    return r.text
  else:
    return False

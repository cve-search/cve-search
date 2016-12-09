#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Minimal class to get the last entries from the CVE database.
#
# Ranking and CPE lookup are optional.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2015 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015-2016	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import itertools
import math

from lib.Config import Configuration
from lib.Toolkit import exploitabilityScore,impactScore
import lib.DatabaseLayer as db

class last():
    def __init__(self, collection="cves", rankinglookup=False,
                 namelookup=False, capeclookup=False, via4lookup=False,
                 subscorelookup=False):

        self.collectionname = collection
        self.rankinglookup  = rankinglookup
        self.namelookup     = namelookup
        self.capeclookup    = capeclookup
        self.subscorelookup = subscorelookup
        self.via4lookup     = via4lookup
        
        self.collection = collection

    def getcapec(self, cweid=None):
        if cweid is None or not self.capeclookup:
            return False
        e = db.getCAPECFor(cweid)
        capec = []
        for f in e:
            capec.append(f)
        return capec

    def getcpe(self, cpeid=None):
        if not(self.namelookup):
            return cpeid
        e = db.getCPE(cpeid)
        if e is None:
            e = db.getAlternativeCPE(cpeid)
            if e is None:
                return cpeid
        if 'id' in e:
            return e['title']

    def getVIA4(self, cveid=None):
        if not(self.via4lookup):
            return cveid
        e = db.getVIA4(cveid)
        return e if e else cveid

    def getcve(self, cveid=None):
        if cveid is not None:
            e = db.getCVE(cveid, collection=self.collection)
            if e is None:
                return None
            if "cwe" in e and self.capeclookup:
                if e['cwe'].lower() != 'unknown':
                    e['capec'] = self.getcapec(cweid=(e['cwe'].split('-')[1]))
            if "vulnerable_configuration" in e:
                vulconf = []
                ranking = []
                for conf in e['vulnerable_configuration']:
                    vulconf.append({'id': conf, 'title': self.getcpe(cpeid=conf)})
                    if self.rankinglookup:
                        rank = self.getranking(cpeid=conf)
                        if rank and rank not in ranking:
                            ranking.append(rank)
                e['vulnerable_configuration'] = vulconf
            if self.rankinglookup and len(ranking) > 0:
                e['ranking'] = ranking
            if self.via4lookup:
                f = self.getVIA4(cveid)
                if isinstance(f, dict):
                    e = dict(itertools.chain(e.items(), f.items()))
            if self.subscorelookup:
                exploitCVSS=exploitabilityScore(e)
                impactCVSS =impactScore(e)
                e['exploitCVSS']=(math.ceil(exploitCVSS*10)/10) if type(exploitCVSS) is not str else exploitCVSS
                e['impactCVSS']=(math.ceil(impactCVSS*10)/10) if type(impactCVSS) is not str else impactCVSS
        else:
            e = None

        return e

    def getranking(self, cpeid=None, loosy=True):

        if cpeid is None:
            return False

        result = False

        if loosy:
            for x in cpeid.split(':'):
                if x is not '':
                    i = db.findRanking(x, regex=True)
                if i is None:
                    continue
                if 'rank' in i:
                    result = i['rank']
        else:
            i = db.findRanking(cpeid, regex=True)
            if i is None:
                return result
            if 'rank' in i:
                result = i['rank']

        return result

    def get(self, limit=5, skip=0):
        entries = []
        for item in db.getCVEs(limit=limit, skip=skip, collection=self.collection):
            if not(self.namelookup) and not(self.rankinglookup):
                entries.append(item)
            elif self.namelookup or self.rankinglookup:
                if "vulnerable_configuration" in item:
                    vulconf = []
                    ranking = []
                    for conf in item['vulnerable_configuration']:
                        vulconf.append(self.getcpe(cpeid=conf))
                        if self.rankinglookup:
                            rank = self.getranking(cpeid=conf)
                            if rank and rank not in ranking:
                                ranking.append(rank)
                    item['vulnerable_configuration'] = vulconf
                    if self.rankinglookup:
                        item['ranking'] = ranking
                if "ranking" in item:
                    if len(item['ranking']) == 0:
                        del(item['ranking'])
                if "cwe" in item and self.capeclookup:
                    if item['cwe'].lower() != 'unknown':
                        item['capec'] = self.getcapec(cweid=(item['cwe'].split('-')[1]))
                entries.append(item)

        return (entries)

    def __exit__(self, type, value, traceback):
        self.dbname.disconnect()

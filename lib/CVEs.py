#!/usr/bin/env python3.1
# -*- coding: utf-8 -*-
#
# Minimal class to get the last entries from the CVE database.
#
# Ranking and CPE lookup are optional.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2015 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 		Pieter-Jan Moreels - pieterjan.moreels@gmail.com

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

class last:

    def __init__(self, collection="cves", rankinglookup=False,
                 namelookup=False, vfeedlookup=False, capeclookup=False,
                 subscorelookup=False, reflookup=False, misplookup=False):

        self.collectionname = collection
        self.rankinglookup = rankinglookup
        self.namelookup = namelookup
        self.vfeedlookup = vfeedlookup
        self.capeclookup = capeclookup
        self.subscorelookup = subscorelookup
        self.misplookup = misplookup
        
        self.collection = collection

        if reflookup:
            self.ref = Configuration.getRedisRefConnection()

    def getcapec(self, cweid=None):
        if cweid is None or not self.capeclookup:
            return False
        e = db.getCAPECFor(cweid)
        capec = []
        for f in e:
            capec.append(f)
        return capec

    def getref(self, cveid=None):
        if cveid is None or not self.ref:
            return False
        ref = self.ref.smembers(cveid)
        return ref

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

    def getvfeed(self, cveid=None):
        if not(self.vfeedlookup):
            return cveid
        e = db.getvFeed(cveid)
        return e if e else cveid

    def getMISP(self, cveid=None):
        if not (self.misplookup):
            return cveid
        e = db.getMISP(cveid)
        return e if e else None

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
            if self.vfeedlookup:
                f = self.getvfeed(cveid=cveid)
                if not isinstance(f, str):
                    g = dict(itertools.chain(e.items(), f.items()))
                    e = g
            if self.subscorelookup:
                exploitCVSS=exploitabilityScore(e)
                impactCVSS =impactScore(e)
                e['exploitCVSS']=(math.ceil(exploitCVSS*10)/10) if type(exploitCVSS) is not str else exploitCVSS
                e['impactCVSS']=(math.ceil(impactCVSS*10)/10) if type(impactCVSS) is not str else impactCVSS
            if self.misplookup:
                misp = self.getMISP(cveid=cveid)
                if misp:
                   misp.pop('id')
                   e['misp']=misp
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


def test_last():
    l = last(rankinglookup=True, vfeedlookup=True, capeclookup=False)
    print (l.getcpe(cpeid="cpe:/o:google:android:2.0"))
    print (l.getranking(cpeid="cpe:/o:google:android:2.0"))
    print (l.get())
    print (l.getcve("CVE-2015-0597"))
    print (l.getcapec("85"))
    l = last(rankinglookup=False, vfeedlookup=True, capeclookup=True)
    print (l.getcve("CVE-2015-0597"))
    print (l.getcapec("200"))
    l = last(reflookup=True)
    print(l.getref("CVE-2015-0597"))
if __name__ == "__main__":
    test_last()

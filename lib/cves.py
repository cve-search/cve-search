#!/usr/bin/env python3.1
# -*- coding: utf-8 -*-
#
# Minimal class to get the last entries from the CVE database.
#
# Ranking and CPE lookup are optional.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2013 Alexandre Dulaunoy - a@foo.be


import pymongo
import itertools

class last:

    def __init__(self, db="cvedb",collection="cves", rankinglookup=False,
            namelookup=False, vfeedlookup=False):

        self.dbname = db
        self.collectionname = collection
        self.rankinglookup = rankinglookup
        self.namelookup = namelookup
        self.vfeedlookup = vfeedlookup

        connect = pymongo.Connection()
        connectdb = connect[self.dbname]
        self.collection = connectdb[self.collectionname]

        if rankinglookup:
            self.ranking = connectdb['ranking']
        if namelookup:
            self.cpe = connectdb['cpe']
        if vfeedlookup:
            self.vfeed = connectdb['vfeed']

    def getcpe(self, cpeid = None):

        if not(self.namelookup):
            return cpeid

        e = self.cpe.find_one({'id': cpeid})

        if e is None:
            return cpeid
        if 'id' in e:
            return e['title']

    def getvfeed(self, cveid = None):

        if not(self.vfeed):
            return cveid

        e = self.vfeed.find_one({'id': cveid})

        if e is None:
            return cveid
        else:
            del e['_id']
            return e

    def getcve(self, cveid = None):

        if cveid is not None:
            e = self.collection.find_one({'id': cveid})
            if e is None:
                return None
            if "vulnerable_configuration" in e:
                vulconf = []
                ranking = []
                for conf in e['vulnerable_configuration']:
                    vulconf.append(self.getcpe(cpeid=conf))
                    if self.rankinglookup:
                        rank = self.getranking(cpeid=conf)
                        if rank and rank not in ranking:
                            ranking.append(rank)
                e['vulnerable_configuration'] = vulconf
                if self.rankinglookup:
                    e['ranking'] = ranking
                if self.vfeedlookup:
                    f = self.getvfeed(cveid=cveid)
                    if not isinstance(f, str):
                        g = dict(itertools.chain(e.items(), f.items()))
                        e = g
        else:
            e = None

        return e

    def getranking(self, cpeid = None, loosy = True):

        if cpeid is None:
            return False

        result = False

        if loosy:
            for x in cpeid.split(':'):
                if x is not '':
                    i = self.ranking.find_one({'cpe': {'$regex':x}})
                if i is None:
                    continue
                if 'rank' in i:
                    result = i['rank']
        else:
            i = self.ranking.find_one({'cpe': {'$regex':cpeid}})
            if i is None:
                return result
            if 'rank' in i:
                result = i['rank']

        return result


    def get(self, limit=5, skip=0):
        entries = []
        for item in self.collection.find({}).sort("Modified",-1).skip(skip).limit(limit):
            if not(self.namelookup) and not(self.rankinglookup):
                entries.append(item)
            elif self.namelookup or self.rankinglookup:
                if "vulnerable_configuration" in item:
                    vulconf = []
                    ranking =[]
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
                entries.append(item)

        return (entries)

    def __exit__(self, type, value, traceback):
        self.dbname.disconnect()

def test_last():
    l = last(rankinglookup=True, vfeedlookup=True)
    print (l.getcpe(cpeid="cpe:/o:google:android:2.0"))
    print (l.getranking(cpeid="cpe:/o:google:android:2.0"))
    print (l.get())
    print (l.getcve("CVE-2012-0004"))

if __name__ == "__main__":
    test_last()

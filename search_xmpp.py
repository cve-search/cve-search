#!/usr/bin/env python3.1
# -*- coding: utf-8 -*-
#
# Simple XMPP bot to query for the last entries in the CVE database
#
# current command supported is:
#
# last <max>
#
# You need to add the XMPP bot in your roster if you want to communicate
# with it.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012 Alexandre Dulaunoy - a@foo.be


import sys
import logging
import getpass
from optparse import OptionParser

import sleekxmpp
import pymongo
import re
import datetime
import json
# BSON MongoDB include ugly stuff that needs to be processed for standard JSON
from bson import json_util

if sys.version_info < (3, 0):
    from sleekxmpp.util.misc_ops import setdefaultencoding
    setdefaultencoding('utf8')
else:
    raw_input = input

rankinglookup = True

connect = pymongo.Connection()
db = connect.cvedb
collection = db.cves

helpmessage = "\nlast <n> cve entries (output: JSON) \n"
helpmessage = helpmessage + "cvetweet <n> cve entries (output: Text) \n"
helpmessage = helpmessage + "search <query> full-text search on the summary field (output JSON)\n\n"
helpmessage = helpmessage + "For more info about cve-search: http://adulau.github.com/cve-search/"
def lookupcpe(cpeid = None):
    e = db.cpe.find_one({'id': cpeid})
    if e is None:
        return cpeid
    if 'id' in e:
        return e['title']

def findranking(cpe = None, loosy = True):
    if cpe is None:
        return False
    r = db.ranking
    result = False
    if loosy:
        for x in cpe.split(':'):
            if x is not '':
                i = r.find_one({'cpe': {'$regex':x}})
            if i is None:
                continue
            if 'rank' in i:
                result = i['rank']
    else:
        i = r.find_one({'cpe': {'$regex':cpe}})
        print (cpe)
        if i is None:
            return result
        if 'rank' in i:
            result = i['rank']

    return result


def lastentries(limit = 5, namelookup=False):
    entries = []
    for item in collection.find({}).sort("last-modified",-1).limit(limit):
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

def searchentries(query = None, namelookup=True, rankinglookup=True):
    entries = []
    sorttype = -1
    print (query)
    for item in collection.find({'summary': {'$regex' :  re.compile(query, re.IGNORECASE)}}).sort("last-modified",sorttype):
        if not namelookup:
            entries.append(item)
        else:
            if "vulnerable_configuration" in item:
                vulconf = []
                ranking = []
                for conf in item['vulnerable_configuration']:
                    vulconf.append(lookupcpe(cpeid=conf))
                    if rankinglookup:
                        rank = findranking(cpe=conf)
                        if rank and rank not in ranking:
                            ranking.append(rank)

                item['vulnerable_configuration'] = vulconf
                if rankinglookup:
                    item['ranking'] = ranking
            entries.append(item)
    return entries


def cvesearch(query="last", option=None):
    if query=="last":
        if option is None:
            limit = 10
        else:
            limit = int(option)
        return json.dumps(lastentries(limit=limit), sort_keys=True, indent=4, default=json_util.default)
    elif query=="search":
        return json.dumps(searchentries(query=option), sort_keys=True, indent=4, default=json_util.default)
    elif query=="cvetweet":
        text = " "

        if option is None:
            limit =10
        else:
            limit = int(option)

        for t in lastentries(limit=limit):
            text = text+str(t['id'])+" , "+str(t['summary'])+" "+" , ".join(t['references'])+"\n"
        return text
    else:
        return False

class CVEBot(sleekxmpp.ClientXMPP):


    def __init__(self, jid, password):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.message)

    def start(self, event):
        self.send_presence()
        self.get_roster()

    def message(self, msg):
        if msg['type'] in ('chat', 'normal'):
            q = []
            q = (msg['body']).split()
            if q[0] == "last":
                try:
                    option=q[1]
                except IndexError:
                    option=None
                msg.reply(cvesearch(query="last", option=option)).send()
            elif q[0] == "search":
                q.pop(0)
                option=' '.join(q)
                msg.reply(cvesearch(query="search", option=option)).send()
            elif q[0] == "cvetweet":
                try:
                    option=q[1]
                except IndexError:
                    option=None
                msg.reply(cvesearch(query="cvetweet", option=option)).send()
            else:
                msg.reply(helpmessage).send()

if __name__ == '__main__':
    optp = OptionParser()
    optp.add_option('-q', '--quiet', help='set logging to ERROR',
                    action='store_const', dest='loglevel',
                    const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG',
                    action='store_const', dest='loglevel',
                    const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM',
                    action='store_const', dest='loglevel',
                    const=5, default=logging.INFO)
    optp.add_option('-n', '--cpenamelookup', help='CPE name lookup',
                    action='store_false', dest='cpelookup',default=True)
    optp.add_option("-j", "--jid", dest="jid",
                    help="JID to use")
    optp.add_option("-p", "--password", dest="password",
                    help="password to use")

    opts, args = optp.parse_args()

    # Setup logging.
    logging.basicConfig(level=opts.loglevel,
                        format='%(levelname)-8s %(message)s')

    if opts.jid is None:
        opts.jid = raw_input("Username: ")
    if opts.password is None:
        opts.password = getpass.getpass("Password: ")
    # Basic skeleton based on CVEBot from sleekxmpp library
    xmpp = CVEBot(opts.jid, opts.password)
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0004') # Data Forms
    xmpp.register_plugin('xep_0060') # PubSub
    xmpp.register_plugin('xep_0199') # XMPP Ping


    if xmpp.connect():
        xmpp.process(block=True)
        print("Done")
    else:
        print("Unable to connect.")


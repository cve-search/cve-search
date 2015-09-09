#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Simple XMPP bot to query for the last entries in the CVE database
#
# current commands supported are:
#
# last <max>
# cvetweet <max>
# browse
# search <vendor>\<product>
# get <cve>
#
# You need to add the XMPP bot in your roster if you want to communicate
# with it.
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2012-2013 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import logging
import getpass
from optparse import OptionParser
import sleekxmpp
import json

from lib.Query import lastentries, apigetcve, apibrowse, apisearch
# BSON MongoDB include ugly stuff that needs to be processed for standard JSON
from bson import json_util

if sys.version_info < (3, 0):
    from sleekxmpp.util.misc_ops import setdefaultencoding
    setdefaultencoding('utf8')
else:
    raw_input = input

runPath = os.path.dirname(os.path.realpath(__file__))

rankinglookup = True

helpmessage = "\nlast <n> cve entries (output: JSON) \n"
helpmessage = helpmessage + "cvetweet <n> cve entries (output: Text) \n"
helpmessage = helpmessage + "browse vendors and products (output: JSON)\n"
helpmessage = helpmessage + "search <vendor>\<product> (output: JSON)\n"
helpmessage = helpmessage + "get <cve-id> (output: JSON)\n"
helpmessage = helpmessage + "For more info about cve-search: http://adulau.github.com/cve-search/"


def cvesearch(query="last", option=None):
    if query == "last":
        if option is None:
            limit = 10
        else:
            limit = int(option)
        if limit > opts.max or limit < 1:
            return "Request not in range 0-%d" % opts.max
        return json.dumps(lastentries(limit=limit), sort_keys=True, indent=4, default=json_util.default)
    elif query == "get":
        if option is None:
            return "A cve-id must be specified"
        return apigetcve(opts.api,cveid=option)
    elif query == "browse":
        return apibrowse(opts.api, vendor=option)
    elif query == "search":
        return apisearch(opts.api, query=option)
    elif query == "cvetweet":
        text = " "

        if option is None:
            limit = 10
        else:
            limit = int(option)
        if limit > opts.max or limit < 1:
            return "Request not in range 0-%d" % opts.max
        for t in lastentries(limit=limit):
            text = text + str(t['id']) + " , " + str(t['summary']) + " " + " , ".join(t['references']) + "\n"
        return text
    elif query == "browse":
        return apibrowse(vendor=option)
    else:
        return False

class CVEBot(sleekxmpp.ClientXMPP):

    def __init__(self, jid, password):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)
        if opts.ipv4 is False:
            self.use_ipv6 = True
        else:
            self.use_ipv6 = False
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.message)
        self.add_event_handler("ssl_invalid_cert", self.ssl_invalid_cert)

    def ssl_invalid_cert(self, cert):
        return

    def start(self, event):
        self.send_presence()
        self.get_roster()

    def message(self, msg):
        if msg['type'] in ('chat', 'normal'):
            q = []
            q = (msg['body']).split()
            try:
                option = q[1]
            except IndexError:
                option = None
            if q[0] == "last":
                msg.reply(cvesearch(query="last", option=option)).send()
            elif q[0] == "browse":
                msg.reply(cvesearch(query="browse", option=option)).send()
            elif q[0] == "get":
                msg.reply(cvesearch(query="get", option=option)).send()
            elif q[0] == "cvetweet":
                msg.reply(cvesearch(query="cvetweet", option=option)).send()
            elif q[0] == "search":
                msg.reply(cvesearch(query="search", option=option)).send()
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
                    action='store_false', dest='cpelookup', default=True)
    optp.add_option("-j", "--jid", dest="jid",
                    help="JID to use")
    optp.add_option('-m', '--max', dest='max', type='int', default=20, help='Maximum elements to return (default: 20)')
    optp.add_option('-a', '--api', dest='api', default='http://127.0.0.1:5000/', help='HTTP API url (default: http://127.0.0.1:5000)')
    optp.add_option("-4", "--ipv4", action='store_true', dest="ipv4",
                    default=False, help="Force IPv4 only")
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
    xmpp.register_plugin('xep_0030')  # Service Discovery
    xmpp.register_plugin('xep_0004')  # Data Forms
    xmpp.register_plugin('xep_0060')  # PubSub
    xmpp.register_plugin('xep_0199')  # XMPP Ping

    if xmpp.connect():
        xmpp.process(block=True)
        print("Done")
    else:
        print("Unable to connect.")

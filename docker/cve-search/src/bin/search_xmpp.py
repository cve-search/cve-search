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
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2012-2018  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import getpass
import json
import logging
import os
import sys

import sleekxmpp
from bson import json_util
from optparse import OptionParser

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from web.templates._old_.api import API


if sys.version_info < (3, 0):
    from sleekxmpp.util.misc_ops import setdefaultencoding

    setdefaultencoding("utf8")
else:
    raw_input = input


rankinglookup = True

helpmessage = (
    "last [<n>]                - last n cve entries (default: 10) (output: JSON)\n"
)
helpmessage += "get <cve-id>              - get cve info (output: JSON)\n"
helpmessage += "browse                    - list of vendors (output: JSON)\n"
helpmessage += "browse <vendor>           - list of products of vendor (output: JSON)\n"
helpmessage += "search <vendor> <product> - list of cves for product (output: JSON)\n"
helpmessage += (
    "cvetweet <n>              - summary of <n> last cve entries (output: Text)\n"
)
helpmessage += "cvetweet <cve-id>         - summary of cve <cve-id> (output: Text) \n\n"
helpmessage += "For more info about cve-search: http://adulau.github.com/cve-search/"

api = API()


def cvesearch(query="last", option=None):
    def last(option):
        try:
            limit = int(option) if option else 10
        except:
            return "Please specify the number of CVEs"

        if limit > opts.max or limit < 1:
            return "Request not in range 0-%d" % opts.max
        return api.api_last(limit)

    def cve(option):
        if option is None:
            return "A cve-id must be specified"
        return api.api_cve(option)

    if query in ["last", "recent"]:
        return last(option)
    elif query in ["get", "cve"]:
        return cve(option)
    elif query in ["browse", "vendor"]:
        return api.api_browse(option)
    elif query in ["search", "product"]:
        parts = option.split()
        if len(parts) < 2:
            return "Usage: search <vendor> <product>"
        return api.api_search(parts[0], parts[1])
    elif query in ["cvetweet", "tweet"]:
        text = ""
        cves = []
        if option.lower().startswith("cve-"):
            cves.append(cve(option))
        else:
            cves = last(option)

        for t in cves:
            text += (
                str(t["id"])
                + " , "
                + str(t["summary"])
                + " "
                + " , ".join(t["references"])
                + "\n"
            )
        return text
    else:
        return helpmessage


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

    def format_message(self, message):
        if type(message) in [dict, list]:
            message = json.dumps(
                message, sort_keys=True, indent=4, default=json_util.default
            )
        else:
            message = str(message)
        return message

    def ssl_invalid_cert(self, cert):
        return

    def start(self, event):
        self.send_presence()
        self.get_roster()

    def message(self, msg):
        if msg["type"] in ("chat", "normal"):
            q = (msg["body"]).split(" ", 1)
            option = q[1] if len(q) == 2 else None

            reply = cvesearch(query=q[0], option=option)
            msg.reply(self.format_message(reply)).send()


if __name__ == "__main__":
    optp = OptionParser()
    optp.add_option(
        "-q",
        "--quiet",
        help="set logging to ERROR",
        action="store_const",
        dest="loglevel",
        const=logging.ERROR,
        default=logging.INFO,
    )
    optp.add_option(
        "-d",
        "--debug",
        help="set logging to DEBUG",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.INFO,
    )
    optp.add_option(
        "-v",
        "--verbose",
        help="set logging to COMM",
        action="store_const",
        dest="loglevel",
        const=5,
        default=logging.INFO,
    )
    optp.add_option(
        "-n",
        "--cpenamelookup",
        help="CPE name lookup",
        action="store_false",
        dest="cpelookup",
        default=True,
    )
    optp.add_option("-j", "--jid", dest="jid", help="JID to use")
    optp.add_option(
        "-m",
        "--max",
        dest="max",
        type="int",
        default=20,
        help="Maximum elements to return (default: 20)",
    )
    optp.add_option(
        "-4",
        "--ipv4",
        action="store_true",
        dest="ipv4",
        default=False,
        help="Force IPv4 only",
    )
    optp.add_option("-p", "--password", dest="password", help="password to use")

    opts, args = optp.parse_args()

    # Setup logging.
    logging.basicConfig(level=opts.loglevel, format="%(levelname)-8s %(message)s")

    if opts.jid is None:
        opts.jid = raw_input("Username: ")
    if opts.password is None:
        opts.password = getpass.getpass("Password: ")
    # Basic skeleton based on CVEBot from sleekxmpp library
    xmpp = CVEBot(opts.jid, opts.password)
    xmpp.register_plugin("xep_0030")  # Service Discovery
    xmpp.register_plugin("xep_0004")  # Data Forms
    xmpp.register_plugin("xep_0060")  # PubSub
    xmpp.register_plugin("xep_0199")  # XMPP Ping

    if xmpp.connect():
        xmpp.process(block=True)
        print("Done")
    else:
        print("Unable to connect.")

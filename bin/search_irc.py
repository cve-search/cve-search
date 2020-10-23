#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Simple IRC bot to query for the last entries in the CVE database
#
# current command supported is:
#
# last <max>
# cvetweet <max>
# browse
# search <vendor>\<product>
# get <cve>
#
# You need to connect the IRC bot to the IRC Server you want to access it from.
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import argparse
import json
import os
import signal
import ssl
import sys

import irc.bot
import irc.strings
from bson import json_util

from web.templates._old_.api import API

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))


argParser = argparse.ArgumentParser(description="IRC bot to query cve-search")
argParser.add_argument("-s", type=str, help="server ip", default="localhost")
argParser.add_argument("-p", type=int, help="server port)", default=6667)
argParser.add_argument("-n", type=str, help="nickname", default="cve-search")
argParser.add_argument("-w", type=str, help="password")
argParser.add_argument("-u", type=str, help="username", default="cve-search")
argParser.add_argument("-c", nargs="*", help="channel list", default=["cve-search"])
argParser.add_argument("-t", type=str, help="trigger prefix", default=".")
argParser.add_argument(
    "-v", action="store_true", help="channel list", default=["cve-search"]
)
argParser.add_argument("-m", type=int, help="maximum query amount", default=20)
argParser.add_argument("--ssl", action="store_true", help="Use SSL")
args = argParser.parse_args()


class IRCBot(irc.bot.SingleServerIRCBot):
    def __init__(
        self, channel, nickname, server, port, password=None, username=None, **kwargs
    ):
        if not username:
            username = nickname
        irc.bot.SingleServerIRCBot.__init__(
            self, [(server, port)], nickname, username, **kwargs
        )
        self.channel = channel
        self.api = API()

    def on_nicknameinuse(self, c, e):
        c.nick(c.get_nickname() + "_")

    def on_welcome(self, c, e):
        if args.v:
            print("Server welcomed us")
        for chan in self.channel:
            if not chan.startswith("#"):
                chan = "#%s" % chan
            if args.v:
                print("joining %s" % chan)
            c.join(chan)

    def on_privmsg(self, c, e):
        self.do_command(e, e.arguments[0])

    def on_pubmsg(self, c, e):
        line = e.arguments[0]
        if line.startswith(args.t):
            self.do_command(e, line[len(args.t) :])
        return

    def reply(self, e, reply):
        if type(reply) in [dict, list]:
            # reply = json.dumps(reply, sort_keys=True, indent=4, default=json_util.default, ensure_ascii=True)
            reply = json.dumps(
                reply, sort_keys=True, ensure_ascii=True, default=json_util.default
            )
        else:
            reply = str(reply)

        if e.target == self.connection.nickname:
            target = e.source.nick
        else:
            target = e.target
        _list = reply.split("\n")
        chunk_size = (
            512 - 12 - len(e.target)
        )  # 512 - len("PRIVMSG") - len(" :") - CR/LF - target

        _list = [
            [x[i : i + chunk_size] for i in range(0, len(x), chunk_size)] for x in _list
        ]
        _list = [item for sublist in _list for item in sublist]  # flatten list
        for r in _list[:4]:
            self.connection.privmsg(target, r)

    def do_command(self, e, cmd):
        def last(option):
            limit = int(option) if option else 10
            if limit > args.m or limit < 1:
                self.reply(e, "Request not in range 0-%d" % args.m)
            self.reply(e, self.api.api_last(limit))

        def cve(option):
            if option is None:
                return "A cve-id must be specified"
            return self.api.api_cve(option)

        if not cmd:
            pass
        parts = cmd.split(" ", 1)
        cmd = parts[0]
        option = parts[1] if len(parts) == 2 else None

        if cmd == "die":
            self.die()
        elif cmd in ["last", "recent"]:
            self.reply(e, last(option))
        elif cmd in ["get", "cve"]:
            self.reply(e, cve(option))
        elif cmd in ["browse", "vendor"]:
            self.reply(e, self.api.api_browse(option))
        elif cmd in ["search", "product"]:
            parts = option.split()
            if len(parts) < 2:
                return self.reply(e, "Usage: search <vendor> <product>")
            return self.reply(e, self.api.api_search(parts[0], parts[1]))
        elif cmd in ["cvetweet", "tweet"]:
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
            return self.reply(e, text)
        else:
            self.reply(e, "Not understood: " + cmd)


# signal handlers
def sig_handler(sig, frame):
    print("Caught signal: %s\nShutting down" % sig)
    bot.die()


def main():
    server = args.s
    port = args.p
    nick = args.n
    password = args.w
    user = args.u
    chans = args.c
    global bot

    if args.ssl:
        print("using ssl")
        ssl_factory = irc.connection.Factory(wrapper=ssl.wrap_socket)
        bot = IRCBot(
            chans,
            nick,
            server,
            port,
            password=password,
            username=user,
            connect_factory=ssl_factory,
        )
    else:
        bot = IRCBot(chans, nick, server, port, password=password, username=user)
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    if args.v:
        print("Connecting to server")
    bot.start()


if __name__ == "__main__":
    main()

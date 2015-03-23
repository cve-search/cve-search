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
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015	 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import argparse
import json
# BSON MongoDB include ugly stuff that needs to be processed for standard JSON
from bson import json_util

import irc.bot
import irc.strings

from lib.Query import lastentries, apigetcve, apibrowse, apisearch

argParser = argparse.ArgumentParser(description='IRC bot to query cve-search')
argParser.add_argument('-s', type=str, help='server ip', default='localhost')
argParser.add_argument('-p', type=int, help='server port)', default=6667)
argParser.add_argument('-n', type=str, help='nickname', default='cve-search')
argParser.add_argument('-w', type=str, help='password')
argParser.add_argument('-u', type=str, help='username', default='cve-search')
argParser.add_argument('-c', nargs="*", help='channel list', default=['cve-search'])
argParser.add_argument('-t', type=str, help='trigger prefix', default='.')
argParser.add_argument('-v', action='store_true', help='channel list', default=['cve-search'])
argParser.add_argument('-m', type=int, help='maximum query amount', default=20)
args = argParser.parse_args()

class IRCBot(irc.bot.SingleServerIRCBot):
  def __init__(self, channel, nickname, server, port, password=None, username=None):
    if not username:
      username=nickname
    irc.bot.SingleServerIRCBot.__init__(self, [(server, port)], nickname, username)
    self.channel = channel

  def on_nicknameinuse(self, c, e):
    c.nick(c.get_nickname() + "_")

  def on_welcome(self, c, e):
    if args.v:
      print("Server welcomed us")
    for chan in self.channel:
      if not chan.startswith('#'):chan=("#%s"%chan)
      if args.v:
        print("joining %s"%chan)
      c.join(chan)

  def on_privmsg(self, c, e):
    self.do_command(e, e.arguments[0])

  def on_pubmsg(self, c, e):
    line = e.arguments[0]
    if line.startswith(args.t):
      self.do_command(e, line[len(args.t):])
    return

  def reply(self, e, reply):
    c = self.connection
    if e.target == c.nickname:
      target=e.source.nick
    else:
      target=e.target
    list = reply.split('\n')
    for r in list:
      c.privmsg(target, r)

  def do_command(self, e, cmd):
    words = cmd.split(' ')
    if len(words)>=2:
      cmd=words[0]
      option=words[1]
    else:
      option=None

    if cmd == "die":
      self.die()
    elif cmd == "last":
      if option is None:
        limit = 10
      else:
        limit = int(option)
      if limit > args.m or limit < 1:
        self.reply(e, "Request not in range 0-%d" % args.m)
      self.reply(e, json.dumps(lastentries(limit=limit), sort_keys=True, indent=4, default=json_util.default))
    elif cmd == "get":
      if option is None:
        self.reply(e, "A cve-id must be specified")
      self.reply(e, apigetcve(cveid=option))
    elif cmd == "browse":
      self.reply(e, apibrowse(vendor=option))
    elif cmd == "search":
      self.reply(e, apisearch(query=option))
    elif cmd == "cvetweet":
      text = " "
      if option is None:
        limit = 10
      else:
        limit = int(option)
      if limit > args.m or limit < 1:
        return "Request not in range 0-%d" % args.m
      for t in lastentries(limit=limit):
        text = text + str(t['id']) + " , " + str(t['summary']) + " " + " , ".join(t['references']) + "\n"
      self.reply(e, text)
    elif cmd == "browse":
        self.reply(e, apibrowse(vendor=option))

    else:
      self.reply(e, "Not understood: " + cmd)

import signal

# signal handlers
def sig_handler(sig, frame):
    print('Caught signal: %s\nShutting down' % sig)
    bot.die()

def main():
  server = args.s
  port = args.p
  nick = args.n
  password = args.w
  user = args.u
  chans = args.c
  global bot
  bot=IRCBot(chans, nick, server, port, password=password,username=user)
  signal.signal(signal.SIGTERM, sig_handler)
  signal.signal(signal.SIGINT, sig_handler)
  if args.v:
    print("Connecting to server")
  bot.start()

if __name__ == "__main__":
  main()

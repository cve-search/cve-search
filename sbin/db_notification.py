#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Notification database
#  includes the user who will receive a notification
#  when a new CVE is published and matching their monitored CPE
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import argparse
import lib.DatabaseLayer as dbLayer
from lib.Config import Configuration

argParser = argparse.ArgumentParser(description='Notification database management for cve-search', epilog='')
argParser.add_argument('-c', action='append', help='CPE name(s) to add (e.g. google:chrome)')
argParser.add_argument('-g', type=str, help='Name of the organization (e.g. mycompany)')
argParser.add_argument('-d', action='append', help='Destination(s) of matching CPE (mailto:foo@bar.com)')
argParser.add_argument('-a', action='store_true', default=False, help='Add a notification entry')
argParser.add_argument('-r', action='store_true', default=False, help='Remove a notification entry')
argParser.add_argument('-v', action='store_true', default=False, help='Verbose logging')
argParser.add_argument('-n', action='store_true', default=False, help='Run notification')
argParser.add_argument('-f', action='store_true', default=False, help='Flush state')
argParser.add_argument('-l', action='store_true', default=False, help='List notification entries')
args = argParser.parse_args()


def checkreq():

    if args.c is None:
        print ("You need at least one cpe or partial cpe entry (-c) \n")
        argParser.print_help()
        exit(1)
    if args.g is None:
        print ("Organization is missing (-g) \n")
        argParser.print_help()
        exit(1)

def searchcve(cpe=None):
    if cpe is None:
        return False
    cve = dbLayer.cvesForCPE(cpe)
    return cve


def updatestate(org=None, cve=None):
    if cve is None or org is None:
        return False
    for c in cve:
        r.sadd("s:" + org, c)


def sendnotification(org=None, cve=None):
    if org is None or cve is None:
        return False
    for destination in r.smembers("d:" + org):
        for c in cve:
            print ("notification of " + c + " to " + destination)

# Redis db 10 (cpe)
# Redis db 11 (notification)

# Set of notification for an organization set(d:orgname) -> notification destination
# Set of cpe value for an organization set(c:orgname) -> cpe values
# Set of organizations set(orgs) -> organisations

# Set of state notification set(s:orgs) -> CVEs
r = Configuration.getRedisNotificationsConnection()

if args.a and args.r and args.n and args.f and args.l:
    argParser.print_help()
    exit(1)

if args.a:
    checkreq()
    if not r.sismember("orgs", args.g):
        if args.v:
            print ("Organization " + args.g + " added.")
        r.sadd("orgs", args.g)

    for cpe in args.c:
        r.sadd("c:" + args.g, cpe)
        if args.v:
            print (cpe + " added")

    if not r.scard("d:" + args.g):
        if args.g:
            for destination in args.d:
                r.sadd("d:" + args.g, destination)
        else:
            print ("destination missing for " + args.g + " you need at least one destination -d")
            exit(1)

elif args.r:
    checkreq()
    for cpe in args.c:
        r.srem("c:" + args.g, cpe)
        if args.v:
            print (cpe + " removed")

    if r.scard("c:" + args.g) < 1:
        r.srem("orgs", args.g)
        if args.v:
            print ("org " + args.g + " removed")

elif args.n:
    for org in r.smembers("orgs"):
        if args.v:
            print("Notification for " + org)
        knowncve = set()
        for cpe in r.smembers("c:" + org):
            if args.v:
                print("CPE " + cpe)
            for cve in searchcve(cpe=cpe):
                knowncve.add(cve['id'])
        if r.exists("s:" + org):
            x = r.smembers("s:" + org)
            diff = knowncve.difference(x)
            if diff:
                sendnotification(org=org, cve=diff)

        updatestate(org=org, cve=knowncve)

elif args.f:
    for org in r.smembers("orgs"):
        r.delete('s:' + org)
        if args.v:
            print ("State for " + org + " deleted")

elif args.l:
    for org in r.smembers("orgs"):
        print (org)
        for cpe in r.smembers("c:" + org):
            print (" " + cpe)
        for destination in r.smembers("d:" + org):
            print ("->" + destination)

else:
    argParser.print_help()

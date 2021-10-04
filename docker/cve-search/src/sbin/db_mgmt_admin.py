#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Admin creator script
#
# Creates an admin account in the database
# Only master accounts are allowed to add and remove users
# First account registered is the master account
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

import argparse
import getpass
import os
import sys
from hmac import compare_digest

from pymongo.errors import ConnectionFailure

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.DatabaseHandler import DatabaseHandler
from lib.DatabaseLayer import (
    getSize,
)

dbh = DatabaseHandler()

# args
argParser = argparse.ArgumentParser(
    description="Admin account creator for the mongo database"
)
argParser.add_argument("-a", help="<name> Add an account", default=False)
argParser.add_argument("-c", help="Change the password of an account", default=None)
argParser.add_argument("-r", help="Remove account", default=False)
argParser.add_argument("-p", help="Promote account to master", default=False)
argParser.add_argument("-d", help="Demote account to normal user", default=False)
argParser.add_argument("-l", help="Make the user local-only", action="store_true")
args = argParser.parse_args()

# vars
col = "mgmt_users"

exits = {
    "userInDb": "User already exists in database",
    "userNotInDb": "User does not exist in database",
    "userpasscombo": "Master user/password combination does not exist",
    "passwordMatch": "The passwords don't match!",
    "noMaster": "Not a master account!",
    "lastMaster": "This user is the last admin in the database and thus can not be removed",
    "dummy": "_dummy_ is a placeholder, and thus cannot be used",
}

# functions


def verifyPass(password, user):
    if not dbh.connection.userExists(user):
        sys.exit(exits["userNotInDb"])
    if not dbh.connection.verifyUser(user, password):
        sys.exit(exits["userpasscombo"])
    return True


def promptNewPass():
    password = getpass.getpass("New password:")
    verify = getpass.getpass("Verify password:")
    if not compare_digest(password, verify):
        sys.exit(exits["passwordMatch"])
    return password


def masterLogin():
    master = input("Master account username: ")
    if dbh.connection.verifyPass(getpass.getpass("Master password:"), master):
        if not dbh.connection.isMasterAccount(master):
            sys.exit(exits["noMaster"])
    else:
        sys.exit("Master user/password combination does not exist")
    return True


def isLastAdmin(user):
    if dbh.connection.isSingleMaster(user):
        sys.exit(exits["lastMaster"])


# script run
try:
    if args.a:
        username = args.a
        if username.strip() == "_dummy_":
            sys.exit(exits["dummy"])
        if dbh.connection.userExists(username):
            sys.exit(exits["userInDb"])
        # set master if db is empty
        if getSize(col) > 0:
            masterLogin()
            password = promptNewPass()
            dbh.connection.addUser(username, password, localOnly=args.l)
        else:
            password = promptNewPass()
            dbh.connection.addUser(username, password, admin=True, localOnly=args.l)
        sys.exit("User added")
    elif args.c:
        username = args.c
        dbh.connection.verifyPass(getpass.getpass("Old password:"), username)
        password = promptNewPass()
        dbh.connection.changePassword(username, password)
        sys.exit("Password updated")
    elif args.r:
        username = args.r
        if not dbh.connection.userExists(username):
            sys.exit(exits["userNotInDb"])
        dbh.connection.masterLogin()
        dbh.connection.isLastAdmin(username)
        dbh.connection.deleteUser(username)
        sys.exit("User removed from database")
    elif args.p:
        username = args.p
        if not dbh.connection.userExists(username):
            sys.exit(exits["userNotInDb"])
        dbh.connection.masterLogin()
        # promote
        dbh.connection.setAdmin(username, True)
        sys.exit("User promoted")
    elif args.d:
        username = args.d
        if not dbh.connection.userExists(username):
            sys.exit(exits["userNotInDb"])
        dbh.connection.masterLogin()
        dbh.connection.isLastAdmin(username)
        # demote
        dbh.connection.setAdmin(username, False)
        sys.exit("User demoted")

except ConnectionFailure:
    print("Can't connect to the mongo database")
except Exception as e:
    print(e)
    print("Outdated database. Please drop and re-fill your database")

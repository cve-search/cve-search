#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Admin creator script
#
# Creates an admin account in the database
# Only master accounts are allowed to add and remove users
# First account registered is the master account
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015 		Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import pymongo

import argparse
import getpass
from passlib.hash import pbkdf2_sha256

from lib.Config import Configuration
import lib.DatabaseLayer as dbLayer

# args
argParser = argparse.ArgumentParser(description='Admin account creator for the mongo database')
argParser.add_argument('-a', help='<name> Add an account', default=False)
argParser.add_argument('-c', help='Change the password of an account', default=None)
argParser.add_argument('-r', help='Remove account', default=False)
argParser.add_argument('-p', help='Promote account to master', default=False)
argParser.add_argument('-d', help='Demote account to normal user', default=False)
args = argParser.parse_args()

# vars
col = "mgmt_users"
rounds = 8000
saltLength = 10
exits = {'userInDb': 'User already exists in database',
         'userNotInDb': 'User does not exist in database',
         'userpasscombo': 'Master user/password combination does not exist',
         'passwordMatch': "The passwords don't match!",
         'noMaster': 'Not a master account!',
         'lastMaster': 'This user is the last admin in the database and thus can not be removed',
         'dummy': '_dummy_ is a placeholder, and thus cannot be used'}

# functions


def verifyPass(password, user):
    if not dbLayer.userExists(user):
        sys.exit(exits['userNotInDb'])
    dbPass = dbLayer.getUser(user)['password']
    if not pbkdf2_sha256.verify(password, dbPass):
        sys.exit(exits['userpasscombo'])
    return True


def promptNewPass():
    password = getpass.getpass("New password:")
    verify = getpass.getpass("Verify password:")
    if (password != verify):
        sys.exit(exits['passwordMatch'])
    return pbkdf2_sha256.encrypt(password, rounds=rounds, salt_size=saltLength)


def masterLogin():
    master = input("Master account username: ")
    if verifyPass(getpass.getpass("Master password:"), master):
        if not dbLayer.isMasterAccount(master):
            sys.exit(exits['noMaster'])
    else:
        sys.exit('Master user/password combination does not exist')
    return True


def isLastAdmin(user):
    if dbLayer.isSingleMaster(user):
        sys.exit(exits['lastMaster'])

# script run
try:
    if args.a:
        username = args.a
        if username.strip() == "_dummy_":
            sys.exit(exits['dummy'])
        if dbLayer.userExists(username):
            sys.exit(exits['userInDb'])
        # set master if db is empty
        if dbLayer.getSize(col) > 0:
            masterLogin()
            password = promptNewPass()
            dbLayer.addUser(username, password)
        else:
            password = promptNewPass()
            dbLayer.addUser(username, password, admin=True)
        sys.exit("User added")
    elif args.c:
        username = args.c
        verifyPass(getpass.getpass("Old password:"), username)
        password = promptNewPass()
        dbLayer.changePassword(username, password)
        sys.exit("Password updated")
    elif args.r:
        username = args.r
        if not dbLayer.userExists(username):
            sys.exit(exits['userNotInDb'])
        masterLogin()
        isLastAdmin(username)
        dbLayer.deleteUser(username)
        sys.exit('User removed from database')
    elif args.p:
        username = args.p
        if not dbLayer.userExists(username):
            sys.exit(exits['userNotInDb'])
        masterLogin()
        # promote
        dbLayer.setAdmin(username, True)
        sys.exit('User promoted')
    elif args.d:
        username = args.d
        if not dbLayer.userExists(username):
            sys.exit(exits['userNotInDb'])
        masterLogin()
        isLastAdmin(username)
        # demote
        dbLayer.setAdmin(username, False)
        sys.exit('User demoted')

except pymongo.errors.ConnectionFailure:
    print("Can't connect to the mongo database")
except Exception as e:
    print(e)
    print("Outdated database. Please drop and re-fill your database")

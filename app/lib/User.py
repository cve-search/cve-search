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
runPath = os.path.dirname(os.path.realpath(__file__))

from flask.ext.login import UserMixin

from lib.Config import Configuration

# connect to db
db = Configuration.getMongoConnection()
collection = db.mgmt_users


class UserNotFoundError(Exception):
    pass


class User(UserMixin):

    '''Simple User class'''
    if not Configuration.loginRequired():
        # dummy account for when logon is not required.
        USERS = {"_dummy_": "_dummy_"}
    else:
        USERS = {}
    for user in collection.find({}):
        USERS[user['username']] = user['password']

    def __init__(self, id):
        if not id in self.USERS:
            raise UserNotFoundError()
        self.id = id
        self.password = self.USERS[id]

    @classmethod
    def get(self_class, id):
        '''Return user instance of id, return None if not exist'''
        try:
            return self_class(id)
        except UserNotFoundError:
            return None

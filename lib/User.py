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

from flask_login import UserMixin

from lib.Config import Configuration
import lib.DatabaseLayer as db

# Exception
class UserNotFoundError(Exception):
    pass

# Class
class User(UserMixin):
    def __init__(self, id, auth_instance):
        '''Simple User class'''
        if not Configuration.loginRequired():
            # dummy account for when logon is not required.
            self.id = "_dummy_"
        else:
            if not auth_instance.isCVESearchUser(id):
                raise UserNotFoundError()
            self.id = id
            self.authenticator = auth_instance

    def authenticate(self, password):
        return self.authenticator.validateUser(self.id, password)

    @classmethod
    def get(self_class, id , auth_instance):
        '''Return user instance of id, return None if not exist'''
        try:
            return self_class(id, auth_instance)
        except UserNotFoundError:
            return None

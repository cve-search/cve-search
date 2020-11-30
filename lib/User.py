#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2015-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
from flask_login import UserMixin

runPath = os.path.dirname(os.path.realpath(__file__))

from lib.Config import Configuration


# Exception
class UserNotFoundError(Exception):
    pass


# Class
class User(UserMixin):
    def __init__(self, id, auth_instance):
        """Simple User class"""
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
    def get(cls, id, auth_instance):
        """Return user instance of id, return None if not exist"""
        try:
            return cls(id, auth_instance)
        except UserNotFoundError:
            return None

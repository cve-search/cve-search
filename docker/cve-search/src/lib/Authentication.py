#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Plugin manager
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2016-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import datetime
import importlib
import logging
import os
import sys
import uuid
from abc import ABC, abstractmethod

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.DatabaseHandler import DatabaseHandler
from lib.LogHandler import AppLogger
from lib.Config import Configuration as conf
from lib.Singleton import Singleton

logging.setLoggerClass(AppLogger)

# Constants
UNREACHABLE = -1
WRONG_CREDS = 0
AUTHENTICATED = 1


class AuthenticationMethod(ABC):

    @abstractmethod
    def validateUser(self, user, pwd):
        raise NotImplementedError


class AuthenticationHandler(metaclass=Singleton):
    def __init__(self, **kwargs):
        self.logger = logging.getLogger(__name__)
        self.methods = []
        self._load_methods()
        self.api_sessions = {}
        self.dbh = DatabaseHandler()

    def _load_methods(self):
        self.methods = []
        if not os.path.exists(conf.getAuthLoadSettings()):
            self.logger.warning("Could not find auth loader file!")
            return
        # Read and parse plugin file
        data = open(conf.getAuthLoadSettings(), "r").read()
        data = [
            x.split(maxsplit=2)
            for x in data.splitlines()
            if not x.startswith("#") and x
        ]
        for x in [x for x in data if len(x) in [2, 3]]:
            try:
                x.extend([""] * (3 - len(x)))  # add empty args if none exist
                method, authType, args = x
                if authType.lower() not in [
                    "required",
                    "sufficient",
                ]:  # Skip if authType not known
                    continue
                # Create object
                args = {y.split("=")[0]: y.split("=")[1] for y in args.split()}
                i = importlib.import_module("lib.authenticationMethods.%s" % method)
                authMethod = getattr(i, method.split("/")[-1])(**args)
                # Add object to list
                self.methods.append((method, authType.lower(), authMethod))
                self.logger.info("Loaded Auth Method {}".format(x[0]))
            except Exception as e:
                self.logger.error("Failed to load Auth Method {}:  -> {}".format(x[0], e))

    def isCVESearchUser(self, user):
        return self.dbh.connection.userExists(user)

    def validateUser(self, user, password):
        user_obj = self.dbh.connection.getUser(user)
        if not user_obj:
            return False
        # 'local_only' users bypass other auth methods. If the user is not,
        #  we try the other auth methods first
        if not "local_only" in user_obj.keys() or user_obj["local_only"] is False:
            for name, authType, method in self.methods:
                try:
                    result = method.validateUser(user, password)
                    if result is UNREACHABLE:
                        continue  # Skip to next
                    if result is AUTHENTICATED:
                        return True  # Successful
                    if authType == "required" and result is WRONG_CREDS:
                        return False
                    if authType == "sufficient" and result is WRONG_CREDS:
                        continue
                except Exception as e:
                    self.logger.error("Exception trying to authenticate user: {} -> {}".format(name, e))
        # If we reach here, all methods (if any) failed to authenticate the user
        #  so we check the user against the local database.
        return self.dbh.connection.verifyUser(user, password)

    def new_api_session(self, user):
        self.api_sessions[user] = (uuid.uuid4().hex, datetime.datetime.now())
        return self.api_sessions[user][0]

    def get_api_session(self, user, extend=True):
        return self.api_sessions.get(user)

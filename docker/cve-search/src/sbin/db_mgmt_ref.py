#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Import of the VIA4 dataset (vFeed replacement)
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2015-2018  Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2016-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.Sources_process import VIADownloads
from lib.Config import Configuration

# To Do: Implement REDIS

if __name__ == "__main__":

    via = VIADownloads()

    try:
        redis = Configuration.getRedisRefConnection()
        try:
            redis.info()
        except:
            sys.exit(
                "Redis server not running on %s:%s"
                % (Configuration.getRedisHost(), Configuration.getRedisPort())
            )
    except Exception as e:
        print(e)
        sys.exit(1)

    lastmodified = via.populate()

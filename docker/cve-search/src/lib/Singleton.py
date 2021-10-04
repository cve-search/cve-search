#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2017-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

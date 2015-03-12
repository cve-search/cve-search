#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# CPEList class, used in black-and whitelists
#
# Software is free software released under the "Modified BSD license"
#

# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
# make sure these modules are available on your system
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import re

from lib.Toolkit import toStringFormattedCPE

class CPEList:

    def __init__(self, collection, args):
        self.collection = collection
        self.args = args

    # check if there are items in the collection
    def countItems(self):
        return self.collection.count()

    # check if a cpe is in the list
    def check(self, cpe):
        try:
            cpeListElement = {'id': cpe}
            amount = self.collection.find(cpeListElement).count()
            return amount
        except Exception:
            print("Error connecting to the database")
            sys.exit()

    # insert to database
    def insert(self, cpe, cpeType):
        try:
            # split comments from cpe
            if '#' in cpe:
                comments = cpe.split('#')
                del comments[0]
            cpeID = cpe.split('#')[0]
            if cpeType.lower() == "cpe":
                cpeID = toStringFormattedCPE(cpeID)
            # check format
            if cpeID:
                # already in db?
                if self.check(cpeID) == 0:
                    if '#' in cpe:
                        cpeListElement = {'id': cpeID, 'type':cpeType, 'comments': comments}
                    else:
                        cpeListElement = {'id': cpeID, 'type':cpeType}
                    self.collection.insert(cpeListElement)
                    return True
            return False
        except Exception as ex:
            print("Error inserting item in database: %s"%(ex))
            sys.exit()

    # remove a cpe from the list
    def remove(self, cpe):
        try:
            cpe = cpe.strip()
            # translate cpe
            if toStringFormattedCPE(cpe): cpe = toStringFormattedCPE(cpe)
            # check if the cpe is in the list
            amount = self.check(cpe)
            if amount > 0:
                cpeListElement = {'id': cpe}
                self.collection.remove(cpeListElement)
            return amount
        except Exception as ex:
            print("Error removing item from database: {:d}".format(ex))
            sys.exit()

    def update(self, cpeOld, cpeNew):
        try:
            cpeOld = cpeOld.strip()
            cpeNew = cpeNew.strip()
            # translate cpes
            cpeOld = toStringFormattedCPE(cpeOld)
            cpeNew = toStringFormattedCPE(cpeNew)
            if cpeOld and cpeNew:
                # already in db?
                if self.check(cpeOld.split('#')[0]) != 0:
                    if '#' in cpeNew:
                        # there are extra comments
                        cpeID = cpeNew.split('#')[0]
                        cpeID.strip()
                        # allow multiple comments
                        comments = cpeNew.split('#')
                        del comments[0]
                        cpeListElement = {'id': cpeID, 'comments': comments}
                    else:
                        cpeListElement = {'id': cpeNew}
                    cpeDeleteElement = {'id': cpeOld.split('#')[0]}
                    self.collection.update(cpeDeleteElement, cpeListElement, upsert=False, multi=False)
                    return True
            return False
        except Exception as ex:
            print(ex)
            print("Error updating item in database: {:d}".format(ex))
            sys.exit()

    # drop the collection
    def dropCollection(self):
        try:
            count = self.countItems()
            self.collection.drop()
            if self.args.v:
                print("collection of {:d} items dropped".format(count))
        except Exception as ex:
            print("Error dropping the database: {:d}".format(ex))
            sys.exit()

    # import a file that represents the cpe list
    def importList(self, importFile):
        count = 0
        # read each line from the import file and regex them to a cpe format
        try:
            for line in importFile:
                print(self.args.t)
                if self.insert(line,self.args.t):
                    count += 1
            if self.args.v:
                print("{:d} products added to the list".format(count))
        except IOError:
            print('Could not open the file')
            sys.exit()

    # export a file that represents the cpe list
    def exportList(self, exportFile):
        count = 0
        # check if file exists already
        if not os.path.exists(exportFile) or self.args.f:
            listed = self.collection.find()
            export = open(exportFile, 'w')
            for listedID in listed:
                count += 1
                commentString = ""
                # check if there are comments
                if 'comments' in listedID:
                    comments = listedID['comments']
                    # separate the comments
                    for comment in comments:
                        commentString = commentString + '#' + comment
                export.write(listedID['id'] + commentString + '\n')
            export.close()
            if self.args.v:
                print("{:d} listed items exported".format(count))
        else:
            print("file already exists")

    # process the arguments and use it to take actions
    def process(self):
        if self.args.d:
            # drop the list
            self.dropCollection()
        elif self.args.i:
            # get import file
            textfile = self.args.i
            # check if the collection is empty
            count = self.countItems()
            if count > 0 and self.args.f is False:
                # not empty and not forced to drop
                print("list already populated")
            else:
                # drop collection and repopulate it
                self.dropCollection()
                self.importList(open(textfile))
        elif self.args.e:
            # get export file
            textfile = self.args.e
            self.exportList(textfile)
        elif self.args.a or self.args.A:
            # get list of cpe's to add
            if self.args.a:
                cpeList = self.args.a
            else:
                cpeList = [x for x in open(self.args.A[0])]
            # add each item from the list
            count = 0
            for cpeID in cpeList:
                if self.insert(cpeID,self.args.t):
                    count += 1
            if self.args.v:
                print("{:d} products added to the list".format(count))
        elif self.args.r or self.args.R:
            # get list of cpe's to remove
            if self.args.r:
                cpeList = self.args.r
            else:
                cpeList = [x for x in open(self.args.R[0])]
            # remove each item from the list
            count = 0
            for cpeID in cpeList:
                amount = self.remove(cpeID)
                count += amount
            if self.args.v:
                print("{:d} products removed from the list".format(count))

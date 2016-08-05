#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CPEList class, used in black-and whitelists
#
# Software is free software released under the "Modified BSD license"
#

# Copyright (c) 2014-2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
# make sure these modules are available on your system
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import json

from lib.Toolkit import toStringFormattedCPE
import lib.DatabaseLayer as db

class CPEList:

    def __init__(self, collection, args):
        self.collection = collection.title()
        self.args = args

    # check if there are items in the collection
    def countItems(self):
        return db.getSize("mgmt_"+self.collection.lower())

    # check if a cpe is in the list
    def check(self, cpe):
        return getattr(db,"isIn"+self.collection)(cpe)

    # insert to database
    def insert(self, cpe, cpeType):
        try:
            # split comments from cpe
            comments = cpe.split('#')
            del comments[0]
            cpeID = cpe.split('#')[0]
            if cpeType.lower() == "cpe":
                cpeID = toStringFormattedCPE(cpeID)
            # check format
            if cpeID:
                # already in db?
                if not self.check(cpeID):
                    getattr(db, "addTo"+self.collection)(cpeID, cpeType, comments)
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
            if self.check(cpe):
                getattr(db, "removeFrom"+self.collection)(cpe)
                return True
            else:
                return False
        except Exception as ex:
            print("Error removing item from database: %s"%(ex))
            sys.exit()

    def update(self, cpeOld, cpeNew, cpeType):
        try:
            cpeOld = cpeOld.strip()
            cpeNew = cpeNew.strip()
            # translate cpes
            cpeOld = toStringFormattedCPE(cpeOld)
            cpeNew = toStringFormattedCPE(cpeNew)
            if cpeOld and cpeNew:
                # already in db?
                if self.check(cpeOld.split('#')[0]):
                    cpeID = cpeNew.split('#')[0]
                    cpeID.strip()
                    # comments
                    comments = cpeNew.split('#')
                    del comments[0]
                    getattr(db, "update"+self.collection)(cpeOld.split('#')[0], cpeID, cpeType, comments)
                    return True
            return False
        except Exception as ex:
            print(ex)
            print("Error updating item in database: %s"%(ex))
            sys.exit()

    # drop the collection
    def dropCollection(self):
        try:
            count = self.countItems()
            db.drop("mgmt_"+self.collection.lower())
            if self.args.v:
                print("collection of %s items dropped"%(count))
        except Exception as ex:
            print("Error dropping the database: %s"%(ex))
            sys.exit()

    # import a file that represents the cpe list
    def importList(self, importFile):
        count = 0
        # read each line from the import file and regex them to a cpe format
        try:
            for line in json.load(importFile):
                try:
                    t = line['type']
                    if t not in ['cpe', 'targetsoftware', 'targethardware']:
                      continue
                    cpe = line['id']
                    if 'comments' in line:
                        cpe += "#" + "#".join(line['comments'])
                    if self.insert(cpe, t):
                        count += 1
                except:
                    continue
            if self.args.v:
                print("%s products added to the list"%(count))
        except IOError:
            print('The list is corrupted!')
            sys.exit()

    # export a file that represents the cpe list
    def exportList(self, exportFile=None):
        listed = getattr(db, "get"+self.collection)()
        output = json.dumps(listed, sort_keys=True, indent=2)
        if exportFile == None:
            return output
        else:
            if not os.path.exists(exportFile) or self.args.f:
                export = open(exportFile, 'w')
                export.write(output)
                export.close()
                if self.args.v:
                    print("%s listed items exported"%(len(listed)))
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
                print("%s products added to the list"%(count))
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
                print("%s products removed from the list"%(count))

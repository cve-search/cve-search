#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Plugin manager
#
# Software is free software released under the "GNU Affero General Public License v3.0"
#
# Copyright (c) 2016-2018  Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import logging
import sys
import os
import importlib

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.LogHandler import AppLogger
from lib.DatabaseLayer import getCVE
from lib.Config import Configuration as conf
from lib.Config import ConfigReader
from lib.Singleton import Singleton

logging.setLoggerClass(AppLogger)


class PluginManager(metaclass=Singleton):
    def __init__(self):
        self.plugins = {}
        self.logger = logging.getLogger(__name__)

    def loadPlugins(self):
        settingsReader = ConfigReader(conf.getPluginsettings())
        if not os.path.exists(conf.getPluginLoadSettings()):
            self.logger.warning("Could not find plugin loader file!")
            return
        # Read and parse plugin file
        data = open(conf.getPluginLoadSettings(), "r").read()
        data = [x.split() for x in data.splitlines() if not x.startswith("#")]
        for x in [x for x in data if len(x) == 2]:
            try:
                if x[1].lower() == "load" or x[1].lower() == "default":
                    # Load plugins
                    i = importlib.import_module(x[0].replace("/", "."))
                    plugin = getattr(i, x[0].split("/")[-1])()
                    plugin.setUID(plugin.getName().replace(" ", "_"))
                    # Ensure UID's unique
                    while True:
                        if plugin.getUID() in self.plugins.keys():
                            plugin.setUID(plugin.getUID() + "_")
                        else:
                            break
                    # Load settings if needed
                    if x[1].lower() == "load":
                        plugin.loadSettings(settingsReader)
                    # Set load state
                    plugin.setLoadState(x[1])
                    # Add to list
                    self.plugins[plugin.getUID().strip()] = plugin
                    self.logger.info("Loaded plugin %s" % x[0])
            except Exception as e:
                self.logger.error("Failed to load module %s: " % x[0])
                self.logger.error("-> %s" % e)

    # Get's - Plug-in manager
    def getPlugins(self):
        return sorted(self.plugins.values(), key=lambda k: k.getName())

    def getWebPlugins(self):
        webPlugins = []
        for plugin in self.getPlugins():
            if plugin.isWebPlugin():
                webPlugins.append(plugin)
        return webPlugins

    def getWebPluginsWithPage(self, **args):
        plugins = []
        for plug in self.getWebPlugins():
            try:
                page = plug.getPage(**args)
                if page and page[0]:  # Make sure there is a page
                    plugins.append(plug)
            except Exception as e:
                self.logger.error("Failed to check webpage from module %s: " % (plug.getName()))
                self.logger.error("-> %s" % e)
        return plugins

    # Get's - Plug-in specific
    def getCVEActions(self, cve, **args):
        actions = []
        for plugin in self.getWebPlugins():
            try:
                actions_ = plugin.getCVEActions(cve, **args)
                if actions_:
                    for action in actions_:
                        action["auth"] = plugin.requiresAuth
                        action["plugin"] = plugin.getUID()
                        actions.append(action)
            except Exception as e:
                self.logger.error(
                    "[!] Plugin %s failed on fetching CVE actions!" % plugin.getName()
                )
                self.logger.error("[!]  -> %s" % e)
        return actions

    def requiresAuth(self, plugin):
        if plugin.strip() in self.plugins.keys():  # Check if plugin exists
            return self.plugins[plugin].requiresAuth
        else:
            return False

    def getFilters(self, **args):
        filters = []
        for plugin in self.getWebPlugins():
            try:
                filters_ = plugin.getFilters(**args)
                if filters_:
                    for filter_ in filters_:
                        filter_["auth"] = plugin.requiresAuth
                        filter_["plugin"] = plugin.getUID()
                        filters.append(filter_)
            except Exception as e:
                self.logger.error("Plugin %s failed on fetching filters!" % plugin.getName())
                self.logger.error("-> %s" % e)
        return filters

    # Get's - Plug-in specific with stored data
    def cvePluginInfo(self, cve, **args):
        cveInfo = []
        for plugin in self.getWebPlugins():
            try:
                data = plugin.cvePluginInfo(cve, **args)
                if type(data) == dict and "title" in data and "data" in data:
                    cveInfo.append(data)
            except Exception as e:
                self.logger.error(
                    "Plugin %s failed on fetching CVE plugin info!"
                    % plugin.getName()
                )
                self.logger.error("-> %s" % e)
        return cveInfo

    def getSearchResults(self, text, **args):
        result = {"data": []}
        results = []
        # Get all data
        for plugin in self.plugins.values():
            data = plugin.search(text, **args)
            # Validate format
            if type(data) == dict:
                data = [data]
            if type(data) == list and all(
                [(type(x) == dict and "n" in x and "d" in x) for x in data]
            ):
                results.extend(data)
        # Sort through data
        for collection in results:
            for item in collection["d"]:
                # Check if already in result data
                try:
                    if not any(item == entry["id"] for entry in result["data"]):
                        entry = getCVE(item)
                        entry["reason"] = collection["n"]
                        result["data"].append(entry)
                except:
                    pass
        return result

    # Actions
    def onCVEOpen(self, cve, **args):
        for plugin in self.getWebPlugins():
            plugin.onCVEOpen(cve, **args)

    def onCVEAction(self, cve, plugin, action, **args):
        if plugin.strip() in self.plugins.keys():  # Check if plugin exists
            if self.plugins[plugin].isWebPlugin():  # Check if plugin is web plugin
                try:
                    return self.plugins[plugin].onCVEAction(cve, action, **args)
                except Exception as e:
                    self.logger.error(
                        "Failed to perform %s action on module %s: "
                        % (action, plugin)
                    )
                    self.logger.error("-> %s" % e)

    def openPage(self, name, **args):
        if name.strip() in self.plugins.keys():  # Check if plugin exists
            if self.plugins[name].isWebPlugin():  # Check if plugin is web plugin
                pageInfo = self.plugins[name].getPage(**args)
                if type(pageInfo) == tuple:
                    page, content = pageInfo
                    if page:
                        return "plugins/%s" % page, content
                    else:
                        return None
                else:
                    return "error.html", {"status": {"except": "plugin-page-missing"}}
            else:
                return "error.html", {"status": {"except": "plugin-not-webplugin"}}
        return "error.html", {"status": {"except": "plugin-not-loaded"}}

    def openSubpage(self, name, subpage, **args):
        if name.strip() in self.plugins.keys():  # Check if plugin exists
            if self.plugins[name].isWebPlugin():  # Check if plugin is web plugin
                pageInfo = self.plugins[name].getSubpage(subpage, **args)
                if type(pageInfo) == tuple:
                    page, content = pageInfo
                    if page:
                        return "plugins/%s" % page, content
                # Else, the page is missing, so we send None to throw a 404
                return None
            else:
                return "error.html", {"status": {"except": "plugin-not-webplugin"}}
        return "error.html", {"status": {"except": "plugin-not-loaded"}}

    def doFilter(self, filters, **args):
        plug_fils = {
            key[5:]: value
            for (key, value) in filters.items()
            if key.startswith("plug_")
        }
        filters_ = []
        for plugin in self.getWebPlugins():
            try:
                filter_ = plugin.doFilter(plug_fils, **args)
                if filter_:
                    if type(filter_) is dict:
                        filters_.append(filter_)
                    elif type(filter_) is list:
                        filters_.extend(filter_)
            except Exception as e:
                self.logger.error("Plugin %s failed on applying filters!" % plugin.getName())
                self.logger.error("-> %s" % e)
        return filters_

    def mark(self, cves, **args):
        for plugin in self.getWebPlugins():
            for cve in cves:
                try:
                    marks = plugin.mark(cve["id"], **args)
                    if marks and type(marks) == tuple and len(marks) == 2:
                        if marks[0]:
                            cve["icon"] = marks[0]
                        if marks[1]:
                            cve["color"] = marks[1]
                except Exception as e:
                    self.logger.error("Plugin %s failed on marking cves!" % plugin.getName())
                    self.logger.error("-> %s" % e)
        return cves

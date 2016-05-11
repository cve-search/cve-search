#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Plugin manager
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import sys
import os
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import importlib

import lib.DatabaseLayer as db
from lib.Config import Configuration as conf
from lib.Config import ConfigReader
from lib.Plugins import Plugin, WebPlugin
from flask.ext.login import current_user

class PluginManager():
  def __init__(self):
    self.plugins = {}
  
  def loadPlugins(self):
    settingsReader = ConfigReader(conf.getPluginsettings())
    if not os.path.exists(conf.getPluginLoadSettings()):
        print("[!] Could not find plugin loader file!")
        return
    # Read and parse plugin file
    data = open(conf.getPluginLoadSettings(), "r").read()
    data = [x.split("\t") for x in data.split("\n") if not x.startswith("#") and x]
    data = [[x.strip() for x in y if x.strip()] for y in data]
    uids = []
    for x in [x for x in data if len(x) == 2]:
      try:
        if x[1].lower() == "load" or x[1].lower() == "default":
          # Load plugins
          i = importlib.import_module(x[0].replace("/", "."))
          plugin = getattr(i, x[0].split("/")[-1])()
          plugin.setUID(plugin.getName().replace(" ", "_"))
          # Ensure UID's unique
          while True:
            if plugin.getUID() in uids: plugin.setUID(plugin.getUID()+"_")
            else: break
          # Load settings if needed
          if x[1].lower() == "load":
            plugin.loadSettings(settingsReader)
          # Add to list
          self.plugins[plugin.getUID().strip()] = plugin
          print("[+] Loaded plugin %s"%x[0])
      except Exception as e:
        print("[!] Failed to load module %s: "%x[0])
        print("[!]  -> %s"%e)

  def onCVEOpen(self, cve, **args):
    for plugin in self.getWebPlugins():
      plugin.onCVEOpen(cve, **args)

  def onCVEAction(self, cve, plugin, action, **args):
    if plugin.strip() in self.plugins.keys(): # Check if plugin exists
      if self.plugins[plugin].isWebPlugin():  # Check if plugin is web plugin
        try:
          return self.plugins[plugin].onCVEAction(cve, action, **args)
        except Exception as e:
          print("[!] Failed to perform %s action on module %s: "%(action, plugin))
          print("[!]  -> %s"%e)

  def getPlugins(self):
    return self.plugins.values()

  def getWebPlugins(self):
    webPlugins = []
    for plugin in self.plugins.values():
      if plugin.isWebPlugin():
        webPlugins.append(plugin)
    return webPlugins

  def getWebPluginsWithPage(self, **args):
    plugins = []
    for plug in self.getWebPlugins():
      page = plug.getPage(**args)
      if page and page[0]: # Make sure there is a page
        plugins.append(plug)
    return plugins

  def getCVEActions(self, cve, **args):
    actions = []
    for plugin in self.getWebPlugins():
      try:
        for action in plugin.getCVEActions(cve, **args):
          action['auth'] = plugin.requiresAuth
          action['plugin'] = plugin.getUID()
          actions.append(action)
      except Exception as e:
        print("[!] Plugin %s failed on fetching CVE actions!"%plugin.getName())
        print("[!]  -> %s"%e)
    return actions

  def requiresAuth(self, plugin):
    if plugin.strip() in self.plugins.keys(): # Check if plugin exists
      return self.plugins[plugin].requiresAuth
    else: return False

  def openPage(self, name, **args):
    if name.strip() in self.plugins.keys(): # Check if plugin exists
      if self.plugins[name].isWebPlugin():  # Check if plugin is web plugin
        pageInfo = self.plugins[name].getPage(**args)
        if type(pageInfo) == tuple:
          page, content = pageInfo
          if page: return ("plugins/%s"%page, content)
          else:    return None
        else:
          return ("error.html", {'status': {'except': 'plugin-page-missing'}})
      else:
        return ("error.html", {'status': {'except': 'plugin-not-webplugin'}})
    return ("error.html", {'status': {'except': 'plugin-not-loaded'}})

  def openSubpage(self, subpage, **args):
    if name.strip() in self.plugins.keys(): # Check if plugin exists
      if self.plugins[name].isWebPlugin():  # Check if plugin is web plugin
        pageInfo = self.plugins[name].getSubpage(subpage, **args)
        if type(pageInfo) == tuple:
          page, content = pageInfo
          if page: return ("plugins/%s"%page, content)
        # Else, the page is missing, so we send None to throw a 404
        return None
      else:
        return ("error.html", {'status': {'except': 'plugin-not-webplugin'}})
    return ("error.html", {'status': {'except': 'plugin-not-loaded'}})

  def cvePluginInfo(self, cve, **args):
    cveInfo = []
    for plugin in self.getWebPlugins():
      try:
        data = plugin.cvePluginInfo(cve, **args)
        if type(data) == dict and 'title' in data and 'data' in data:
          cveInfo.append(data)
      except Exception as e:
        print("[!] Plugin %s failed on fetching CVE plugin info!"%plugin.getName())
        print("[!]  -> %s"%e)
    return cveInfo

  def getSearchResults(self, text):
    result = {'data':[]}
    results = []
    # Get all data
    for plugin in self.plugins.values():
      data = plugin.search(text)
      # Validate format
      if type(data) == list and all([(type(x) == dict and 'n' in x and 'd' in x) for x in data]):
        results.extend(data)
    for collection in results:
      for item in collection['d']:
        # Check if already in result data
        if not any(item['id']==entry['id'] for entry in result['data']):
          entry=db.getCVE(item['id'])
          entry['reason']=collection['n']
          result['data'].append(entry)
    return result

# Filters
  def getFilters(self, **args):
    filters = []
    for plugin in self.getWebPlugins():
      try:
        for filter_ in plugin.getFilters(**args):
          filter_['auth']   = plugin.requiresAuth
          filter_['plugin'] = plugin.getUID()
          filters.append(filter_)
      except Exception as e:
        print("[!] Plugin %s failed on fetching filters!"%plugin.getName())
        print("[!]  -> %s"%e)
    return filters

  def doFilter(self, filters, **args):
    plug_fils = {key[5:]: value for (key, value) in filters.items() if key.startswith('plug_')}
    filters_ = []
    for plugin in self.getWebPlugins():
      try:
        filter_ = plugin.doFilter(plug_fils, **args)
        if filter_:
          if   type(filter_) is dict: filters_.append(filter_)
          elif type(filter_) is list: filters_.extend(filter_)
      except Exception as e:
        print("[!] Plugin %s failed on applying filters!"%plugin.getName())
        print("[!]  -> %s"%e)
    return filters_

  def mark(self, cves, **args):
    for plugin in self.getWebPlugins():
      for cve in cves:
        try:
          marks = plugin.mark(cve['id'], **args)
          if marks and type(marks) == tuple and len(marks) == 2:
            if marks[0]: cve['icon']  = marks[0]
            if marks[1]: cve['color'] = marks[1]
        except Exception as e:
          print("[!] Plugin %s failed on marking cves!"%plugin.getName())
          print("[!]  -> %s"%e)
    return cves

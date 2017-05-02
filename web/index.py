#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Minimal web interface to cve-search to display the last entries
# and view a specific CVE.
#
# Software is free software released under the "Modified BSD license"
#

# Copyright (c) 2013-2016 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import jinja2
import os
import re
import subprocess
import sys
import urllib
_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

from flask       import abort, jsonify, request, redirect, render_template, send_file
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from io          import TextIOWrapper, BytesIO
from redis       import exceptions as redisExceptions

import lib.CVEs          as cves
import lib.DatabaseLayer as db
import lib.Query         as query
import lib.Toolkit       as tk
import sbin.db_blacklist as bl
import sbin.db_whitelist as wl

from lib.Authentication import AuthenticationHandler
from lib.Config         import Configuration
from lib.PluginManager  import PluginManager
from lib.User           import User
from web.minimal        import Minimal
from web.advanced_api   import Advanced_API

class Index(Minimal, Advanced_API):
  #############
  # Variables #
  #############

  def __init__(self):
    # TODO: make auth handler and plugin manager singletons
    Advanced_API.__init__(self)
    Minimal.__init__(self)
    self.minimal = False
    self.auth_handler  = AuthenticationHandler()
    self.plugManager   = PluginManager()
    self.login_manager = LoginManager()
    self.plugManager.loadPlugins()
    self.login_manager.init_app(self.app)
    self.login_manager.user_loader(self.load_user)
    self.redisdb = Configuration.getRedisVendorConnection()

    self.defaultFilters.update({'blacklistSelect': 'on', 'whitelistSelect': 'on',
                                'unlistedSelect': 'show',})
    self.args.update({'minimal': False})
    self.pluginArgs = {"current_user":   current_user, "plugin_manager": self.plugManager}

    routes = [{'r': '/cve/<cveid>',                             'm': ['GET'],  'f': self.cve},
              {'r': '/_get_plugins',                            'm': ['GET'],  'f': self._get_plugins},
              {'r': '/plugin/_get_cve_actions',                 'm': ['GET'],  'f': self._get_cve_actions},
              {'r': '/plugin/<plugin>',                         'm': ['GET'],  'f': self.openPlugin},
              {'r': '/plugin/<plugin>/subpage/<page>',          'm': ['GET'],  'f': self.openPluginSubpage},
              {'r': '/plugin/<plugin>/_cve_action/<action>',    'm': ['GET'],  'f': self._jsonCVEAction},
              {'r': '/login',                                   'm': ['POST'], 'f': self.login_check},
              {'r': '/logout',                                  'm': ['POST'], 'f': self.logout},
              {'r': '/admin',                                   'm': ['GET'],  'f': self.admin},
              {'r': '/admin/',                                  'm': ['GET'],  'f': self.admin},
              {'r': '/admin/change_pass',                       'm': ['GET'],  'f': self.change_pass},
              {'r': '/admin/request_token',                     'm': ['GET'],  'f': self.request_token},
              {'r': '/admin/updatedb',                          'm': ['GET'],  'f': self.updatedb},
              {'r': '/admin/whitelist/import',                  'm': ['POST'], 'f': self.listImport},
              {'r': '/admin/blacklist/import',                  'm': ['POST'], 'f': self.listImport},
              {'r': '/admin/whitelist/export',                  'm': ['GET'],  'f': self.listExport},
              {'r': '/admin/blacklist/export',                  'm': ['GET'],  'f': self.listExport},
              {'r': '/admin/whitelist/drop',                    'm': ['POST'], 'f': self.listDrop},
              {'r': '/admin/blacklist/drop',                    'm': ['POST'], 'f': self.listDrop},
              {'r': '/admin/whitelist',                         'm': ['GET'],  'f': self.listView},
              {'r': '/admin/blacklist',                         'm': ['GET'],  'f': self.listView},
              {'r': '/admin/addToList',                         'm': ['GET'],  'f': self.listAdd},
              {'r': '/admin/removeFromList',                    'm': ['GET'],  'f': self.listRemove},
              {'r': '/admin/editInList',                        'm': ['GET'],  'f': self.listEdit},
              {'r': '/admin/listmanagement',                    'm': ['GET'],  'f': self.listManagement},
              {'r': '/admin/listmanagement/<vendor>',           'm': ['GET'],  'f': self.listManagement},
              {'r': '/admin/listmanagement/<vendor>/<product>', 'm': ['GET'],  'f': self.listManagement},
              {'r': '/admin/listmanagement/add',                'm': ['GET'],  'f': self.listManagementAdd},
              {'r': '/login',                                   'm': ['POST'], 'f': self.login_check}]
    for route in routes: self.addRoute(route)


  #############
  # Functions #
  #############
  def generate_full_query(self, f):
    query = self.generate_minimal_query(f)
    if current_user.is_authenticated():
        if f['blacklistSelect'] == "on":
            regexes = db.getRules('blacklist')
            if len(regexes) != 0:
                exp = "^(?!" + "|".join(regexes) + ")"
                query.append({'$or': [{'vulnerable_configuration': re.compile(exp)},
                                      {'vulnerable_configuration': {'$exists': False}},
                                      {'vulnerable_configuration': []} ]})
        if f['whitelistSelect'] == "hide":
            regexes = db.getRules('whitelist')
            if len(regexes) != 0:
                exp = "^(?!" + "|".join(regexes) + ")"
                query.append({'$or': [{'vulnerable_configuration': re.compile(exp)},
                                      {'vulnerable_configuration': {'$exists': False}},
                                      {'vulnerable_configuration': []} ]})
        if f['unlistedSelect'] == "hide":
            wlregexes = tk.compile(db.getRules('whitelist'))
            blregexes = tk.compile(db.getRules('blacklist'))
            query.append({'$or': [{'vulnerable_configuration': {'$in': wlregexes}},
                                  {'vulnerable_configuration': {'$in': blregexes}}]})
    return query


  def markCPEs(self, cve):
    blacklist = tk.compile(db.getRules('blacklist'))
    whitelist = tk.compile(db.getRules('whitelist'))

    for conf in cve['vulnerable_configuration']:
        conf['list'] = 'none'
        conf['match'] = 'none'
        for w in whitelist:
            if w.match(conf['id']):
                conf['list'] = 'white'
                conf['match'] = w
        for b in blacklist:
            if b.match(conf['id']):
                conf['list'] = 'black'
                conf['match'] = b
    return cve


  def filter_logic(self, filters, skip, limit=None):
    query = self.generate_full_query(filters)
    limit = limit if limit else self.args['pageLength']
    cve   = db.getCVEs(limit=limit, skip=skip, query=query)
    # marking relevant records
    if current_user.is_authenticated():
        if filters['whitelistSelect'] == "on":   cve = self.list_mark('white', cve)
        if filters['blacklistSelect'] == "mark": cve = self.list_mark('black', cve)
    self.plugManager.mark(cve, **self.pluginArgs)
    cve = list(cve)
    return cve


  def addCPEToList(self, cpe, listType, cpeType=None):
    def addCPE(cpe, cpeType, funct):
      return True if funct(cpe, cpeType) else False

    if not cpeType: cpeType='cpe'

    if listType.lower() in ("blacklist", "black", "b", "bl"):
      return addCPE(cpe, cpeType, bl.insertBlacklist)
    if listType.lower() in ("whitelist", "white", "w", "wl"):
      return addCPE(cpe, cpeType, wl.insertWhitelist)


  def list_mark(self, listed, cveList):
    if listed not in ['white', 'black']: return list(cves)
    items = tk.compile(db.getRules(listed+'list'))
    # check the cpes (full or partially) in the black/whitelist
    for i, cve in enumerate(list(cveList)): # the list() is to ensure we don't have a pymongo cursor object
      for c in cve['vulnerable_configuration']:
        if any(regex.match(c) for regex in items):
          cveList[i][listed+'listed'] = 'yes'
    return cveList


  def filterUpdateField(self, data):
    if not data: return data
    returnvalue = []
    for line in data.split("\n"):
      if (not line.startswith("[+]Success to create index") and
        not line == "Not modified" and
        not line.startswith("Starting")):
          returnvalue.append(line)
    return "\n".join(returnvalue)


  def adminInfo(self, output=None):
    return {'stats':        db.getDBStats(True),
            'plugins':      self.plugManager.getPlugins(),
            'updateOutput': self.filterUpdateField(output),
            'token':        db.getToken(current_user.id)}


  # user management
  def load_user(self, id):
    return User.get(id, self.auth_handler)



  ##########
  # ROUTES #
  ##########
  # /cve/<cveid>
  def cve(self, cveid):
    cveid = cveid.upper()
    cvesp = cves.last(rankinglookup=True, namelookup=True, via4lookup=True, capeclookup=True,subscorelookup=True)
    cve = cvesp.getcve(cveid=cveid)
    if cve is None:
      return render_template('error.html',status={'except':'cve-not-found','info':{'cve':cveid}})
    cve = self.markCPEs(cve)

    self.plugManager.onCVEOpen(cveid, **self.pluginArgs)
    pluginData = self.plugManager.cvePluginInfo(cveid, **self.pluginArgs)
    return render_template('cve.html', cve=cve, plugins=pluginData)


  # /_get_plugins
  def _get_plugins(self):
    if not current_user.is_authenticated(): # Don't show plugins requiring auth if not authenticated
      plugins = [{"name": x.getName(), "link": x.getUID()} for x in
                 self.plugManager.getWebPluginsWithPage(**self.pluginArgs) if not x.requiresAuth]
    else:
      plugins = [{"name": x.getName(), "link": x.getUID()} for x in
                 self.plugManager.getWebPluginsWithPage(**self.pluginArgs)]
    return jsonify({"plugins": plugins})


  # /plugin/_get_cve_actions
  def _get_cve_actions(self):
    cve = request.args.get('cve', type=str)
    if not current_user.is_authenticated(): # Don't show actions requiring auth if not authenticated
      actions = [x for x in self.plugManager.getCVEActions(cve, **self.pluginArgs) if not x['auth']]
    else:
      actions = self.plugManager.getCVEActions(cve, **self.pluginArgs)
    return jsonify({"actions": actions})


  # /plugin/<plugin>
  def openPlugin(self, plugin):
    if self.plugManager.requiresAuth(plugin) and not current_user.is_authenticated():
      return render_template("requiresAuth.html")
    else:
      page, args = self.plugManager.openPage(plugin, **self.pluginArgs)
      if page:
        try:
          return render_template(page, **args)
        except jinja2.exceptions.TemplateSyntaxError: return render_template("error.html", status={'except': 'plugin-page-corrupt'})
        except jinja2.exceptions.TemplateNotFound:    return render_template("error.html", status={'except': 'plugin-page-not-found', 'page': page})
      else: abort(404)


  # /plugin/<plugin>/subpage/<page>
  def openPluginSubpage(self, plugin, page):
    if self.plugManager.requiresAuth(plugin) and not current_user.is_authenticated():
      return render_template("requiresAuth.html")
    else:
      page, args = self.plugManager.openSubpage(plugin, page, **self.pluginArgs)
      if page:
        try:
          return render_template(page, **args)
        except jinja2.exceptions.TemplateSyntaxError: return render_template("error.html", status={'except': 'plugin-page-corrupt'})
        except jinja2.exceptions.TemplateNotFound:    return render_template("error.html", status={'except': 'plugin-page-not-found', 'page': page})
      else: abort(404)


  # /plugin/<plugin>/_cve_action/<action>
  def _jsonCVEAction(self, plugin, action):
    cve = request.args.get('cve', type=str)
    response = self.plugManager.onCVEAction(cve, plugin, action, fields=dict(request.args), **self.pluginArgs)
    if   type(response) is bool and response is True:
      return jsonify({'status': 'plugin_action_complete'})
    elif type(response) is bool and response is False or response is None:
      return jsonify({'status': 'plugin_action_failed'})
    elif type(response) is dict:
      return jsonify(response)


  # /admin
  # /admin/
  def admin(self):
    if Configuration.loginRequired():
        if not current_user.is_authenticated():
            return render_template('login.html')
    else:
        person = User.get("_dummy_", self.auth_handler)
        login_user(person)
    output = None
    if os.path.isfile(Configuration.getUpdateLogFile()):
        with open(Configuration.getUpdateLogFile()) as updateFile:
            separator="==========================\n"
            output=updateFile.read().split(separator)[-2:]
            output=separator+separator.join(output)
    return render_template('admin.html', status="default", **self.adminInfo(output))


  # /admin/change_pass
  @login_required
  def change_pass(self):
    current_pass = request.args.get('current_pass')
    new_pass     = request.args.get('new_pass')
    if current_user.authenticate(current_pass):
      if new_pass:
        db.changePassword(current_user.id , new_pass)
        return jsonify({"status": "password_changed"})
      return jsonify({"status": "no_password"})
    else:
      return jsonify({"status": "wrong_user_pass"})

  # /admin/request_token
  @login_required
  def request_token(self):
    return jsonify({"token": db.generateToken(current_user.id)})

  # /admin/updatedb
  @login_required
  def updatedb(self):
    process = subprocess.Popen([sys.executable, os.path.join(_runPath, "../sbin/db_updater.py"), "-civ"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    output="%s\n\nErrors:\n%s"%(str(out,'utf-8'),str(err,'utf-8')) if err else str(out,'utf-8')
    return jsonify({"updateOutput": output, "status": "db_updated"})


  # /admin/whitelist
  # /admin/blacklist
  @login_required
  def listView(self):
    if request.url_rule.rule.split('/')[2].lower() == 'whitelist':
      return render_template('list.html', rules=db.getWhitelist(), listType="Whitelist")
    else:
      return render_template('list.html', rules=db.getBlacklist(), listType="Blacklist")


  # /admin/whitelist/import
  # /admin/blacklist/import
  @login_required
  def listImport(self, force=None, path=None):
    _list = request.url_rule.split('/')[2]
    file = request.files['file']
    force = request.form.get('force')
    count = wl.countWhitelist() if _list.lower == 'whitelist' else bl.countBlacklist()
    if (count == 0) | (not count) | (force == "f"):
      if _list.lower == 'whitelist':
        wl.dropWhitelist()
        wl.importWhitelist(TextIOWrapper(file.stream))
      else:
        bl.dropBlacklist()
        bl.importBlacklist(TextIOWrapper(file.stream))
      status = _list[0]+"l_imported"
    else:
      status = _list[0]+"l_already_filled"
    return render_template('admin.html', status=status, **self.adminInfo())


  # /admin/whitelist/export
  # /admin/blacklist/export
  @login_required
  def listExport(self, force=None, path=None):
    _list = request.url_rule.rule.split('/')[2]
    bytIO = BytesIO()
    data = wl.exportWhitelist() if _list.lower == 'whitelist' else bl.exportBlacklist()
    bytIO.write(bytes(data, "utf-8"))
    bytIO.seek(0)
    return send_file(bytIO, as_attachment=True, attachment_filename=_list+".txt")


  # /admin/whitelist/drop
  # /admin/blacklist/drop
  @login_required
  def listDrop(self):
    _list = request.url_rule.split('/')[2].lower()
    if _list == 'whitelist':
      wl.dropWhitelist()
    else:
      bl.dropBlacklist()
    return jsonify({"status": _list[0]+"l_dropped"})


  # /admin/addToList
  @login_required
  def listAdd(self):
    cpe = request.args.get('cpe')
    cpeType = request.args.get('type')
    lst = request.args.get('list')
    if cpe and cpeType and lst:
      status = "added_to_list" if self.addCPEToList(cpe, lst, cpeType) else "already_exists_in_list"
      returnList = db.getWhitelist() if lst=="whitelist" else db.getBlacklist()
      return jsonify({"status":status, "rules":returnList, "listType":lst.title()})
    else: return jsonify({"status": "could_not_add_to_list"})


  # /admin/removeFromList
  @login_required
  def listRemove(self):
    cpe = request.args.get('cpe', type=str)
    cpe = urllib.parse.quote_plus(cpe).lower()
    cpe = cpe.replace("%3a", ":")
    cpe = cpe.replace("%2f", "/")
    lst = request.args.get('list', type=str)
    if cpe and lst:
      result=wl.removeWhitelist(cpe) if lst.lower()=="whitelist" else bl.removeBlacklist(cpe)
      status = "removed_from_list" if (result > 0) else "already_removed_from_list"
    else:
      status = "invalid_cpe"
    returnList = db.getWhitelist() if lst=="whitelist" else db.getBlacklist()
    return jsonify({"status":status, "rules":returnList, "listType":lst.title()})


  # /admin/editInList
  @login_required
  def listEdit(self):
    old = request.args.get('oldCPE')
    new = request.args.get('cpe')
    lst = request.args.get('list')
    CPEType = request.args.get('type')
    if old and new:
      result = wl.updateWhitelist(old, new, CPEType) if lst=="whitelist" else bl.updateBlacklist(old, new, CPEType)
      status = "cpelist_updated" if (result) else "cpelist_update_failed"
    else:
      status = "invalid_cpe"
    returnList = list(db.getWhitelist()) if lst=="whitelist" else list(db.getBlacklist())
    return jsonify({"rules":returnList, "status":status, "listType":lst})


  # /admin/listmanagement/<vendor>/<product>
  # /admin/listmanagement/<vendor>
  # /admin/listmanagement
  @login_required
  def listManagement(self, vendor=None, product=None):
    try:
      if product is None:
        # no product selected yet, so same function as /browse can be used
        if vendor:
          vendor = urllib.parse.quote_plus(vendor).lower()
        browseList = query.getBrowseList(vendor)
        vendor = browseList["vendor"]
        product = browseList["product"]
        version = None
      else:
        # product selected, product versions required
        version = query.getVersionsOfProduct(urllib.parse.quote_plus(product).lower())
      return render_template('listmanagement.html', vendor=vendor, product=product, version=version)
    except redisExceptions.ConnectionError:
      return render_template('error.html',
                             status={'except':'redis-connection',
                                     'info':{'host':Configuration.getRedisHost(),'port':Configuration.getRedisPort()}})


  # /admin/listmanagement/add
  @login_required
  def listManagementAdd(self):
    # retrieve the separate item parts
    item     = request.args.get('item', type=str)
    listType = request.args.get('list', type=str)

    pattern = re.compile('^[a-z:/0-9.~_%-]+$')

    if pattern.match(item):
      item = item.split(":")
      added = False
      if len(item) == 1:
        # only vendor, so a check on cpe type is needed
        if self.redisdb.sismember("t:/o", item[0]):
          if self.addCPEToList("cpe:/o:" + item[0], listType): added = True
        if self.redisdb.sismember("t:/a", item[0]):
          if self.addCPEToList("cpe:/a:" + item[0], listType): added = True
        if self.redisdb.sismember("t:/h", item[0]):
          if self.addCPEToList("cpe:/h:" + item[0], listType): added = True
      elif 4 > len(item) > 1:
        # cpe type can be found with a mongo regex query
        result = db.getCVEs(query={'cpe_2_2': {'$regex': item[1]}})
        if result.count() != 0:
          prefix = ((result[0])['cpe_2_2'])[:7]
          if len(item) == 2:
            if self.addCPEToList(prefix + item[0] + ":" + item[1], listType):
              added = True
          if len(item) == 3:
            if self.addCPEToList(prefix + item[0] + ":" + item[1] + ":" + item[2], listType):
              added = True
      status = "added_to_list" if added else "could_not_add_to_list"
    else:
      status = "invalid_cpe"
    j={"status":status, "listType":listType}
    return jsonify(j)



  # /login
  def login_check(self):
    # validate username and password
    username = request.form.get('username')
    password = request.form.get('password')
    person = User.get(username, self.auth_handler)
    try:
      if person and person.authenticate(password):
        login_user(person)
        return render_template('admin.html', status="logged_in", **self.adminInfo())
      else:
        return render_template('login.html', status="wrong_user_pass")
    except Exception as e:
      print(e)
      return render_template('login.html', status="outdated_database")


  # /logout
  @login_required
  def logout(self):
    logout_user()
    return redirect("/")


if __name__ == '__main__':
  server = Index()
  server.start()

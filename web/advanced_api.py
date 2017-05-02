#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Minimal web interface to cve-search to display the last entries
# and view a specific CVE.
#
# Software is free software released under the "Modified BSD license"
#

# Copyright (c) 2017 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import json
import os
import subprocess
import sys
_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

import lib.DatabaseLayer as db
import sbin.db_blacklist as bl
import sbin.db_whitelist as wl

from bson               import json_util
from flask              import Response, request, render_template
from functools          import wraps
from io                 import StringIO

from lib.Authentication import AuthenticationHandler
from web.api            import API, APIError


class Advanced_API(API):
  def __init__(self):
    super().__init__()
    routes = [{'r': '/api/admin/whitelist',        'm': ['GET'],  'f': self.api_admin_whitelist},
              {'r': '/api/admin/blacklist',        'm': ['GET'],  'f': self.api_admin_blacklist},
              {'r': '/api/admin/whitelist/export', 'm': ['GET'],  'f': self.api_admin_whitelist},
              {'r': '/api/admin/blacklist/export', 'm': ['GET'],  'f': self.api_admin_blacklist},
              {'r': '/api/admin/whitelist/import', 'm': ['PUT'],  'f': self.api_admin_import_whitelist},
              {'r': '/api/admin/blacklist/import', 'm': ['PUT'],  'f': self.api_admin_import_blacklist},
              {'r': '/api/admin/whitelist/drop',   'm': ['POST'], 'f': self.api_admin_drop_whitelist},
              {'r': '/api/admin/blacklist/drop',   'm': ['POST'], 'f': self.api_admin_drop_blacklist},
              {'r': '/api/admin/whitelist/add',    'm': ['PUT'],  'f': self.api_admin_add_whitelist},
              {'r': '/api/admin/blacklist/add',    'm': ['PUT'],  'f': self.api_admin_add_blacklist},
              {'r': '/api/admin/whitelist/remove', 'm': ['PUT'],  'f': self.api_admin_remove_whitelist},
              {'r': '/api/admin/blacklist/remove', 'm': ['PUT'],  'f': self.api_admin_remove_blacklist},
              {'r': '/api/admin/get_token',        'm': ['GET'],  'f': self.api_admin_get_token},
              {'r': '/api/admin/new_token',        'm': ['GET'],  'f': self.api_admin_generate_token},
              {'r': '/api/admin/get_session',      'm': ['GET'],  'f': self.api_admin_get_session},
              {'r': '/api/admin/start_session',    'm': ['GET'],  'f': self.api_admin_start_session},
              {'r': '/api/admin/updatedb',         'm': ['GET'],  'f': self.api_update_db}]

    for route in routes: self.addRoute(route)


  #############
  # Decorator #
  #############
  def getAuth():
    method, auth = (request.headers.get('Authorization')+" ").split(" ", 1) # Adding and removing space to ensure decent split
    name,   key  = (':'+auth.strip()).rsplit(":", 1)
    name = name[1:] # Adding and removing colon to ensure decent split
    return method, name, key

  def authErrors():
    # Check auth
    if not request.headers.get('Authorization'):
      return ({'status': 'error', 'reason': 'Authentication needed'}, 401)
    method, name, token = Advanced_API.getAuth()
    data = None
    if method.lower() not in ['basic', 'token', 'session']:
      data = ({'status': 'error', 'reason': 'Authorization method not allowed'}, 400)
    else:
      try:
        authenticated = False
        if   method.lower() == 'basic':
          authenticator = AuthenticationHandler()
          if authenticator.validateUser(name, token): authenticated = True
        elif method.lower() == 'token':
          if db.getToken(name) == token: authenticated = True
        elif method.lower() == 'session':
          authenticator = AuthenticationHandler()
          if authenticator.api_sessions.get(name) == token: authenticated = True
        if not authenticated: data = ({'status': 'error', 'reason': 'Authentication failed'}, 401)
      except Exception as e:
        print(e)
        data = ({'status': 'error', 'reason': 'Malformed Authentication String'}, 400)
    if data:
      return data
    else: return None

  def token_required(funct):
    @wraps(funct)
    def api_token(*args, **kwargs):
      data = Advanced_API.authErrors()
      if data:
        return Response(json.dumps(data[0], indent=2, sort_keys=True, default=json_util.default), mimetype='application/json'), data[1]
      else: return API.api(funct)(*args, **kwargs)
    return api_token

  ##########
  # ROUTES #
  ##########
  # Overriding api_dbInfo to allow for logged-in users to get more info
  def api_dbInfo(self):
    errors = Advanced_API.authErrors()
    admin = False if errors and errors[0].get('reason') == "Authentication needed" else True
    return API.api(db.getDBStats)(admin)

  # Overriding api_documentation to show the documentation for these functions
  def api_documentation(self):
    return render_template('api.html', advanced = True)

  @token_required
  def api_admin_whitelist(self):
    return db.getWhitelist()

  @token_required
  def api_admin_blacklist(self):
    return db.getBlacklist()

  @token_required
  def api_admin_import_whitelist(self):
    return wl.importWhitelist(StringIO(request.data.decode("utf-8")))

  @token_required
  def api_admin_import_blacklist(self):
    return bl.importBlacklist(StringIO(request.data.decode("utf-8")))

  @token_required
  def api_admin_drop_whitelist(self):
    return wl.dropWhitelist()

  @token_required
  def api_admin_drop_blacklist(self):
    return bl.dropBlacklist()

  @token_required
  def api_admin_add_whitelist(self):
    return wl.insertWhitelist(request.form['cpe'], request.form['type'])

  @token_required
  def api_admin_add_blacklist(self):
    return bl.insertBlacklist(request.form['cpe'], request.form['type'])

  @token_required
  def api_admin_remove_whitelist(self):
    return wl.removeWhitelist(request.form['cpe'])

  @token_required
  def api_admin_remove_blacklist(self):
    return bl.removeBlacklist(request.form['cpe'])

  @token_required # Of course only the login credentials would work
  def api_admin_get_token(self):
    method, name, key =   Advanced_API.getAuth()
    return db.getToken(name)

  @token_required
  def api_admin_generate_token(self):
    method, name, key =   Advanced_API.getAuth()
    return db.generateToken(name)

  @token_required
  def api_admin_get_session(self):
    method, name, key =   Advanced_API.getAuth()
    _session = AuthenticationHandler().get_api_session(name)
    if not _session: raise(APIError("Session not started", 412))
    return _session

  @token_required
  def api_admin_start_session(self):
    method, name, key =   Advanced_API.getAuth()
    return AuthenticationHandler().new_api_session(name)

  @token_required
  def api_update_db(self):
    process = subprocess.Popen([sys.executable, os.path.join(_runPath, "../sbin/db_updater.py"), "-civ"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    return "%s\n\nErrors:\n%s"%(str(out,'utf-8'),str(err,'utf-8')) if err else str(out,'utf-8')

if __name__ == '__main__':
  server = Advanced_API()
  server.start()

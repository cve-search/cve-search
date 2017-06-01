#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# API module of cve-search. Returns queries in JSON format
#
# Software is free software released under the "Modified BSD license"
#

# Copyright (c) 2013-2016 	Alexandre Dulaunoy - a@foo.be
# Copyright (c) 2014-2017 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# imports
import json
import logging
import os
import random
import re
import signal
import sys
import time
import urllib
_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

from bson               import json_util
from bson.json_util import DEFAULT_JSON_OPTIONS
DEFAULT_JSON_OPTIONS.datetime_representation = 2
from dateutil.parser    import parse      as parse_datetime
from flask              import Flask, request, Response, render_template
from functools          import wraps
from logging.handlers   import RotatingFileHandler
from redis              import exceptions as redisExceptions
from tornado.httpserver import HTTPServer
from tornado.ioloop     import IOLoop
from tornado.wsgi       import WSGIContainer
import datetime

import lib.CVEs          as cves
import lib.DatabaseLayer as db
import lib.Query         as query
import lib.Toolkit       as tk

from lib.Config import Configuration

def convertDatetime(dct=None):
  if isinstance(dct,(list, tuple, set)):
    for item in dct:
      convertDatetime(item)
  elif type(dct) is dict:
    for key, val in dct.items():
      if isinstance(val, datetime.datetime):
        dct[key] = val.isoformat()
      if isinstance(val, (dict, list)):
        convertDatetime(val)
  return dct

class APIError(Exception):
  def __init__(self, message, status=500):
    self.message = message
    self.status  = status

class API():
  app = Flask(__name__, static_folder='static', static_url_path='/static')
  app.config['MONGO_DBNAME'] = Configuration.getMongoDB()
  app.config['SECRET_KEY'] = str(random.getrandbits(256))

  def __init__(self):
    routes = [{'r': '/api/',                               'm': ['GET'], 'f': self.api_documentation},
              {'r': '/api/cpe2.3/<path:cpe>',              'm': ['GET'], 'f': self.api_cpe23},
              {'r': '/api/cpe2.2/<path:cpe>',              'm': ['GET'], 'f': self.api_cpe22},
              {'r': '/api/cvefor/<path:cpe>',              'm': ['GET'], 'f': self.api_cvesFor},
              {'r': '/api/cve/<cveid>',                    'm': ['GET'], 'f': self.api_cve},
              {'r': '/api/cwe',                            'm': ['GET'], 'f': self.api_cwe},
              {'r': '/api/cwe/<int:cwe_id>',               'm': ['GET'], 'f': self.api_cwe},
              {'r': '/api/capec/<cweid>',                  'm': ['GET'], 'f': self.api_capec},
              {'r': '/api/last',                           'm': ['GET'], 'f': self.api_last},
              {'r': '/api/last/',                          'm': ['GET'], 'f': self.api_last},
              {'r': '/api/last/<int:limit>',               'm': ['GET'], 'f': self.api_last},
              {'r': '/api/query',                          'm': ['GET'], 'f': self.api_query},
              {'r': '/api/browse',                         'm': ['GET'], 'f': self.api_browse},
              {'r': '/api/browse/',                        'm': ['GET'], 'f': self.api_browse},
              {'r': '/api/browse/<path:vendor>',           'm': ['GET'], 'f': self.api_browse},
              {'r': '/api/search/<vendor>/<path:product>', 'm': ['GET'], 'f': self.api_search},
              {'r': '/api/search/<path:search>',           'm': ['GET'], 'f': self.api_text_search},
              {'r': '/api/link/<key>/<value>',             'm': ['GET'], 'f': self.api_link},
              {'r': '/api/dbInfo',                         'm': ['GET'], 'f': self.api_dbInfo}]
    for route in routes: self.addRoute(route)

  def addRoute(self, route):
    self.app.add_url_rule(route['r'], view_func=route['f'], methods=route['m'])


  #############
  # Decorator #
  #############
  def api(funct):
    @wraps(funct)
    def api_wrapper(*args, **kwargs):
      data = error = None
      # Get data (and possibly errors)
      try:
        data = funct(*args, **kwargs)
      except APIError as e:
        error = ({'status': 'error', 'reason': e.message}, e.status)
      except Exception as e:
        print(e)
        error = ({'status': 'error', 'reason': 'Internal server error'}, 500)
      # Check if data should be returned as html or data
      try:
        returnType = 'application/json'
        if (request.url_rule.rule.lower().startswith("/api/") or
            request.url_rule.rule.lower().endswith(".json") ):
          # Support JSONP
          if request.args.get('callback', False):
            data="%s(%s)"%(request.args.get('callback'), data)

          # Check API version for backwards compatibility. We'll call the old API v1.0
          elif request.headers.get('Version') in ['1.1']:
            # Get the requested return type
            returnType = request.headers.get('Accept', '*/*')
            # Default to JSON
            if   any(t in returnType for t in ['json', 'application/*', 'text/*', '*/*']):
              data = error if error else {'status': 'success', 'data': data}
            elif 'plain' in returnType:
              pass # No need to do anything, but needs to be accepted
            else:
              data = ({'status': 'error', 'reason': 'Unknown Content-type requested'}, 415)
              returnType = 'application/json'
          if type(data) is not str:
            if type(data) is tuple:
              data = list(data)
              data[0] = json.dumps(convertDatetime(dct=data[0]), indent=4, sort_keys=True, default=json_util.default)
            else:
              data = (json.dumps(convertDatetime(dct=data), indent=4, sort_keys=True, default=json_util.default), 200)
          return Response(data[0], mimetype=returnType), data[1]
      except Exception as e:
        print(e)
        pass
      if error and error[1] == 500: raise(APIError(error[0]['reason']))
      return data
    return api_wrapper

  #############
  # FUNCTIONS #
  #############
  def generate_minimal_query(self, f):
    query = []
    # retrieving lists
    if f['rejectedSelect'] == "hide":
      exp = "^(?!\*\* REJECT \*\*\s+DO NOT USE THIS CANDIDATE NUMBER.*)"
      query.append({'summary': re.compile(exp)})

    # cvss logic
    if   f['cvssSelect'] == "above":  query.append({'cvss': {'$gt': float(f['cvss'])}})
    elif f['cvssSelect'] == "equals": query.append({'cvss': float(f['cvss'])})
    elif f['cvssSelect'] == "below":  query.append({'cvss': {'$lt': float(f['cvss'])}})

    # date logic
    if f['timeSelect'] != "all":
      if f['startDate']:
        startDate = parse_datetime(f['startDate'], ignoretz=True, dayfirst=True)
      if f['endDate']:
        endDate   = parse_datetime(f['endDate'],   ignoretz=True, dayfirst=True)

      if   f['timeSelect'] == "from":
        query.append({f['timeTypeSelect']: {'$gt': startDate}})
      elif f['timeSelect'] == "until":
        query.append({f['timeTypeSelect']: {'$lt': endDate}})
      elif f['timeSelect'] == "between":
        query.append({f['timeTypeSelect']: {'$gt': startDate, '$lt': endDate}})
      elif f['timeSelect'] == "outside":
        query.append({'$or': [{f['timeTypeSelect']: {'$lt': startDate}}, {f['timeTypeSelect']: {'$gt': endDate}}]})
    return query

  def filter_logic(self, filters, skip, limit=None):
    query = self.generate_minimal_query(filters)
    limit = limit if limit else self.args['pageLength']
    return db.getCVEs(limit=limit, skip=skip, query=query)

  ##########
  # ROUTES #
  ##########
  # /api
  def api_documentation(self):
    return render_template('api.html')

  # /api/cpe2.3/<cpe>
  @api
  def api_cpe23(self, cpe):
    cpe = tk.toStringFormattedCPE(cpe)
    return cpe if cpe else "None"

  # /api/cpe2.2/<cpe>
  @api
  def api_cpe22(self, cpe):
    cpe = tk.toOldCPE(cpe)
    return cpe if cpe else "None"

  # /api/cvefor/<cpe>
  @api
  def api_cvesFor(self, cpe):
    cpe  = urllib.parse.unquote_plus(cpe)
    return query.cvesForCPE(cpe)

  # /api/cve/<cveid>
  @api
  def api_cve(self, cveid):
    cvesp = cves.last(rankinglookup=True, namelookup=True, via4lookup=True, capeclookup=True)
    cve = cvesp.getcve(cveid=cveid.upper())
    if not cve: raise(APIError('cve not found', 404))
    return cve

  # /api/cwe
  # /api/cwe/<cwe_id>
  @api
  def api_cwe(self, cwe_id=None):
    return db.getCAPECFor(str(cwe_id)) if cwe_id else db.getCWEs()

  # /api/capec/<cweid>
  @api
  def api_capec(self, cweid):
    return db.getCAPEC(cweid)

  # /api/last
  # /api/last/
  # /api/last/<limit>
  @api
  def api_last(self, limit=None):
    limit = limit if limit else 30
    cvesp = cves.last(rankinglookup=True, namelookup=True, via4lookup=True, capeclookup=True)
    cve = cvesp.get(limit=limit)
    return cve

  # /query
  @api
  def api_query(self):
    f={'rejectedSelect': request.headers.get('rejected'),
       'cvss':           request.headers.get('cvss_score'),
       'cvssSelect':     request.headers.get('cvss_modifier'),
       'startDate':      request.headers.get('time_start'),
       'endDate':        request.headers.get('time_end'),
       'timeSelect':     request.headers.get('time_modifier'),
       'timeTypeSelect': request.headers.get('time_type'),
       'skip':           request.headers.get('skip'),
       'limit':          request.headers.get('limit')}
    try:
      skip = int(f['skip']) if f['skip'] else 0
    except:
      raise(APIError('skip must be an int', 400))
    try:
      limit = int(f['limit']) if f['limit'] else 0
    except:
      raise(APIError('limit must be an int', 400))
    return self.filter_logic(f, skip, limit)

  # /api/browse
  # /api/browse/
  # /api/browse/<vendor>
  @api
  def api_browse(self, vendor=None):
    if vendor:
      vendor = urllib.parse.quote_plus(vendor).lower()
    try:
      browseList = query.getBrowseList(vendor)
    except redisExceptions.ConnectionError:
      raise(APIError("Server could not connect to the browsing repository", 503))
    if isinstance(browseList, dict):
      return browseList
    else:
      return {}

  # /api/search/<vendor>/<path:product>
  @api
  def api_search(self, vendor=None, product=None):
    if not (vendor and product): return {}
    search = vendor + ":" + product
    # Not using query.cvesForCPE, because that one gives too much info
    #return json.dumps(db.cvesForCPE(search), default=json_util.default)
    return db.cvesForCPE(search)

  # /api/search/<path:search>
  @api
  def api_text_search(self, search=None):
    return db.getSearchResults(search)

  # /api/link/<key>/<value>
  @api
  def api_link(self, key=None,value=None):
    key=self.htmlDecode(key)
    value=self.htmlDecode(value)
    regex = re.compile(re.escape(value), re.I)
    data = {'cves': db.via4Linked(key, regex)}
    cvssList=[float(x['cvss']) for x in data['cves'] if x.get('cvss')]
    if cvssList:
        data['stats']={'maxCVSS': max(cvssList), 'minCVSS': min(cvssList),'count':len(data['cves'])}
    else:
        data['stats']={'maxCVSS': 0, 'minCVSS': 0, 'count':len(data['cves'])}
    return data

  # /api/dbInfo
  @api
  def api_dbInfo(self):
    return db.getDBStats()


  ########################
  # Web Server Functions #
  ########################
  # signal handlers
  def sig_handler(self, sig, frame):
    print('Caught signal: %s' % sig)
    IOLoop.instance().add_callback(self.shutdown)

  def shutdown(self):
    MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 3
    print('Stopping http server')
    self.http_server.stop()

    print('Will shutdown in %s seconds ...' % MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
    io_loop = IOLoop.instance()
    deadline = time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN

    def stop_loop():
      now = time.time()
      if now < deadline and (io_loop._callbacks or io_loop._timeouts):
        io_loop.add_timeout(now + 1, stop_loop)
      else:
        io_loop.stop()
        print('Shutdown')
    stop_loop()

  def start(self):
    # get properties
    flaskHost = Configuration.getFlaskHost()
    flaskPort = Configuration.getFlaskPort()
    flaskDebug = Configuration.getFlaskDebug()
    # logging
    if Configuration.getLogging():
      logfile = Configuration.getLogfile()
      pathToLog = logfile.rsplit('/', 1)[0]
      if not os.path.exists(pathToLog):
        os.makedirs(pathToLog)
      maxLogSize = Configuration.getMaxLogSize()
      backlog = Configuration.getBacklog()
      file_handler = RotatingFileHandler(logfile, maxBytes=maxLogSize, backupCount=backlog)
      file_handler.setLevel(logging.ERROR)
      formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
      file_handler.setFormatter(formatter)
      self.app.logger.addHandler(file_handler)

    if flaskDebug:
      # start debug flask server
      self.app.run(host=flaskHost, port=flaskPort, debug=flaskDebug)
    else:
      # start asynchronous server using tornado wrapper for flask
      # ssl connection
      print("Server starting...")
      if Configuration.useSSL():
        ssl_options = {"certfile": os.path.join(_runPath, "../", Configuration.getSSLCert()),
                        "keyfile": os.path.join(_runPath, "../", Configuration.getSSLKey())}
      else:
        ssl_options = None
      signal.signal(signal.SIGTERM, self.sig_handler)
      signal.signal(signal.SIGINT,  self.sig_handler)

      self.http_server = HTTPServer(WSGIContainer(self.app), ssl_options=ssl_options)
      self.http_server.bind(flaskPort, address=flaskHost)
      self.http_server.start(0)  # Forks multiple sub-processes
      IOLoop.instance().start()


if __name__ == '__main__':
  server = API()
  server.start()

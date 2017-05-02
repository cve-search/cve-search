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
import os
import re
import sys
import urllib
_runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(_runPath, ".."))

from flask import render_template, request

import lib.DatabaseLayer as db
import lib.Toolkit       as tk

from lib.Config  import Configuration
from web.api     import API, APIError

class Minimal(API):
  #############
  # Variables #
  #############
  defaultFilters={'timeSelect': 'all',
                  'startDate': '', 'endDate': '', 'timeTypeSelect': 'Modified',
                  'cvssSelect': 'all', 'cvss': '', 'rejectedSelect': 'hide'}
  args = {'pageLength':   Configuration.getPageLength(),
          'listLogin':    Configuration.listLoginRequired(),
          'minimal':      True}

  def __init__(self):
    self.minimal = True
    super().__init__()
    routes = [{'r': '/',                               'm': ['GET'],  'f': self.index},
              {'r': '/',                               'm': ['POST'], 'f': self.index_post},
              {'r': '/r/<int:r>',                      'm': ['GET'],  'f': self.index_filter_get},
              {'r': '/r/<int:r>',                      'm': ['POST'], 'f': self.index_filter_post},
              {'r': '/cve/<cveid>',                    'm': ['GET'],  'f': self.cve},
              {'r': '/cwe',                            'm': ['GET'],  'f': self.cwe},
              {'r': '/cwe/<cweid>',                    'm': ['GET'],  'f': self.relatedCWE},
              {'r': '/capec/<capecid>',                'm': ['GET'],  'f': self.capec},
              {'r': '/browse',                         'm': ['GET'],  'f': self.browse},
              {'r': '/browse/',                        'm': ['GET'],  'f': self.browse},
              {'r': '/browse/<vendor>',                'm': ['GET'],  'f': self.browse},
              {'r': '/search/<vendor>/<path:product>', 'm': ['GET'],  'f': self.search},
              {'r': '/search',                         'm': ['POST'], 'f': self.freetext_search},
              {'r': '/link/<key>/<value>',             'm': ['GET'],  'f': self.link}]
    filters = [{'n': 'htmlEncode',      'f': self.htmlEncode},
               {'n': 'htmlDecode',      'f': self.htmlDecode},
               {'n': 'sortIntLikeStr',  'f': self.sortIntLikeStr}]
    context_processors = [self.JSON2HTMLTable]
    error_handlers = [{'e': 404, 'f': self.page_not_found}]

    for route   in routes:             self.addRoute(route)
    for _filter in filters:            self.addFilter(_filter)
    for context in context_processors: self.addContextProcessors(context)
    for handler in error_handlers:     self.app.register_error_handler(handler['e'], handler['f'])

  #############
  # Functions #
  #############
  def addFilter(self, _filter):
    self.app.add_template_filter(_filter['f'], _filter['n'])

  def addContextProcessors(self, context_processor):
    self.app.context_processor(context_processor)

  def getFilterSettingsFromPost(self, r):
    filters = dict(request.form)
    filters = {x: filters[x][0] for x in filters.keys()}
    errors  = False
    # retrieving data
    try:
      cve = self.filter_logic(filters, r)
    except Exception as e:
      cve = db.getCVEs(limit=self.args['pageLength'], skip=r)
      errors = True
    return {'filters': filters, 'cve': cve, 'errors': errors}
    return(filters,cve,errors)


  ##########
  # ROUTES #
  ##########
  # /
  def index(self):
    cve = self.filter_logic(self.defaultFilters, 0)
    return render_template('index.html', cve=cve, r=0, **self.args)

  # /
  def index_post(self):
    args = dict(self.getFilterSettingsFromPost(0), **self.args)
    return render_template('index.html', r=0, **args)

  # /r/<r>
  def index_filter_get(self, r):
    if not r or r < 0: r = 0
    cve = self.filter_logic(self.defaultFilters, r)
    return render_template('index.html', cve=cve, r=r, **self.args)

  # /r/<r>
  def index_filter_post(self, r):
    if not r or r < 0: r = 0
    args = dict(self.getFilterSettingsFromPost(r), **self.args)
    return render_template('index.html', r=r, **args)

  # /cve/<cveid>
  def cve(self, cveid):
    cve = self.api_cve(cveid)
    if not cve:
      return render_template('error.html',status={'except':'cve-not-found','info':{'cve':cveid}},minimal=self.minimal)
    return render_template('cve.html', cve=cve, minimal=self.minimal)

  # /cwe
  def cwe(self):
    cwes=[x for x in self.api_cwe() if x["weaknessabs"].lower()=="class"]
    return render_template('cwe.html', cwes=cwes, capec=None, minimal=self.minimal)

  # /cwe/<cweid>
  def relatedCWE(self, cweid):
    cwes={x["id"]: x["name"] for x in self.api_cwe()}
    return render_template('cwe.html', cwes=cwes, cwe=cweid, capec=db.getCAPECFor(cweid), minimal=self.minimal)

  # /capec/<capecid>
  def capec(self, capecid):
    cwes={x["id"]: x["name"] for x in self.api_cwe()}
    return render_template('capec.html', cwes=cwes, capec=db.getCAPEC(capecid), minimal=self.minimal)

  # /browse
  # /browse/
  # /browse/<vendor>
  def browse(self, vendor=None):
    try:
      data = self.api_browse(vendor)
      if 'product' in data and 'vendor' in data:
       return render_template('browse.html', product=data["product"], vendor=data["vendor"], minimal=self.minimal)
      else:
       return render_template('error.html', minimal=self.minimal, status={'except':'browse_exception', 'info': 'No CPE'})
    except APIError as e:
      return render_template('error.html', minimal=self.minimal, status={'except':'browse_exception', 'info':e.message})

  # /search/<vendor>/<product>
  def search(self, vendor=None, product=None):
    search = vendor + ":" + product
    cve = db.cvesForCPE(search)
    return render_template('search.html', vendor=vendor, product=product, cve=cve, minimal=self.minimal)

  # /search
  def freetext_search(self):
    search = request.form.get('search')
    result = db.getSearchResults(search)
    cve=result['data']
    errors=result['errors'] if 'errors' in result else []
    return render_template('search.html', cve=cve, errors=errors, minimal=self.minimal)

  # /link/<key>/<value>
  def link(self, key=None,value=None):
    key=self.htmlDecode(key)
    value=self.htmlDecode(value)
    regex = re.compile(re.escape(value), re.I)
    cve=db.via4Linked(key, regex)
    cvssList=[float(x['cvss']) for x in cve if x.get('cvss')]
    if cvssList:
        stats={'maxCVSS': max(cvssList), 'minCVSS': min(cvssList),'count':len(cve)}
    else:
        stats={'maxCVSS': 0, 'minCVSS': 0, 'count':len(cve)}
    return render_template('linked.html', via4map=key.split(".")[0], field='.'.join(key.split(".")[1:]),
                           value=value, cve=cve, stats=stats, minimal=self.minimal)


  ###########
  # Filters #
  ###########
  def htmlEncode(self, string):
    return urllib.parse.quote_plus(string).lower()
 
  def htmlDecode(self, string):
    return urllib.parse.unquote_plus(string)

  def sortIntLikeStr(self, datalist):
    return sorted(datalist, key=lambda k: int(k))

  def JSON2HTMLTable(self):
    # Doublequote, because we have to |safe the content for the tags
    def doublequote(data):
      return urllib.parse.quote_plus(urllib.parse.quote_plus(data))

    def JSON2HTMLTableFilter(data, stack = None):
      _return = ""
      if type(stack) == str: stack = [stack]

      if   type(data) == list:
        if len(data) == 1:
          _return += JSON2HTMLTableFilter(data[0], stack)
        else:
          _return += '<ul class="via4">'
          for item in data:
            _return += ('<li>%s</li>'%JSON2HTMLTableFilter(item, stack))
          _return += '</ul>'
      elif type(data) == dict:
        _return += '<table class="invisiTable">'
        for key, val in sorted(data.items()):
          _return += '<tr><td><b>%s</b></td><td>%s</td></tr>'%(key, JSON2HTMLTableFilter(val, stack+[key])) 
        _return += '</table>'
      elif type(data) == str:
        if stack:
          _return += "<a href='/link/"+doublequote('.'.join(stack))+"/"+doublequote(data)+"'>" #link opening
          _return += "<span class='glyphicon glyphicon-link' aria-hidden='true'></span> </a>"
        _return += "<a target='_blank' href='%s'>%s</a>"%(data, data) if tk.isURL(data) else data
      _return += ""
      return _return
    return dict(JSON2HTMLTable=JSON2HTMLTableFilter)


  ##################
  # Error Messages #
  ##################
  def page_not_found(self, e):
    return render_template('404.html', minimal=self.minimal), 404

if __name__ == '__main__':
  server = Minimal()
  server.start()

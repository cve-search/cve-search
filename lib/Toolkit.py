#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Toolkit for functions between scripts
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2014-2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
from dateutil import tz
import dateutil.parser
import time
import re

# Note of warning: CPEs like cpe:/o:microsoft:windows_8:-:-:x64 are given to us by Mitre
#  x64 will be parsed as Edition in this case, not Architecture
def toStringFormattedCPE(cpe,autofill=False):
    cpe=cpe.strip()
    if not cpe.startswith('cpe:2.3:'):
      if not cpe.startswith('cpe:/'): return False
      cpe=cpe.replace('cpe:/','cpe:2.3:')
      cpe=cpe.replace('::',':-:')
      cpe=cpe.replace('~-','~')
      cpe=cpe.replace('~',':-:')
      cpe=cpe.replace('::',':')
      cpe=cpe.strip(':-')
    if autofill:
      e=cpe.split(':')
      for x in range(0,13-len(e)):
        cpe+=':-'
    return cpe

# Note of warning: Old CPE's can come in different formats, and are not uniform. Possibilities are:
# cpe:/a:7-zip:7-zip:4.65::~~~~x64~
# cpe:/a:7-zip:7-zip:4.65:-:~~~~x64~
# cpe:/a:7-zip:7-zip:4.65:-:~-~-~-~x64~
def toOldCPE(cpe):
    cpe=cpe.strip()
    if not cpe.startswith('cpe:/'):
      if not cpe.startswith('cpe:2.3:'): return False
      cpe=cpe.replace('cpe:2.3:','')
      parts = cpe.split(':')
      next = []
      first= "cpe:/"+":".join(parts[:5])
      last = parts[5:]
      if last:
        for x in last:
          next.append('~') if x == "-" else next.append(x)
        if "~" in next:
          pad(next,6,"~")
      cpe="%s:%s"%(first,"".join(next))
      cpe=cpe.replace(':-:','::')
      cpe=cpe.strip(":")
    return cpe

def impactScore(cve):
    score={'NONE':0,'PARTIAL':0.275,'COMPLETE':0.660}
    try:
      C=((cve['impact'])['confidentiality']).upper()
      I=((cve['impact'])['integrity']).upper()
      A=((cve['impact'])['availability']).upper()
      res = 10.41*(1-(1-score[C])*(1-score[I])*(1-score[A]))
      return 10.0 if res > 10.0 else res 
    except Exception as ex:
      print(ex)
      return '-'

def exploitabilityScore(cve):
    cScore={'LOW':0.71,'MEDIUM':0.61,'HIGH':0.35}
    vScore={'NETWORK':1.0,'ADJACENT_NETWORK':0.646,'LOCAL':0.395}
    aScore={'NONE':0.704,'SINGLE_INSTANCE':0.56,'MULTIPLE_INSTANCES':0.45}
    try:
      C=((cve['access'])['complexity']).upper()
      V=((cve['access'])['vector']).upper()
      A=((cve['access'])['authentication']).upper()
      return 20* cScore[C]*vScore[V]*aScore[A]
    except:
      return '-'

def pad(seq, target_length, padding=None):
    length = len(seq)
    if length > target_length:
      return seq
    seq.extend([padding] * (target_length - length))
    return seq

def currentTime(utc):
    timezone = tz.tzlocal()
    utc = dateutil.parser.parse(utc)
    output = utc.astimezone(timezone)
    output = output.strftime('%d-%m-%Y - %H:%M')
    return output

def isURL(string):
    urlTypes= [re.escape(x) for x in ['http://','https://', 'www.']]
    return re.match("^(" + "|".join(urlTypes) + ")", string)

def vFeedName(string):
    string=string.replace('map_','')
    string=string.replace('cve_','')
    return string.title()

def convertDateToDBFormat(string):
    result = None
    try:
        result = time.strptime(string, "%d-%m-%Y")
    except:
        pass
    try:
        result = time.strptime(string, "%d-%m-%y")
    except:
        pass
    try:
        result = time.strptime(string, "%d/%m/%Y")
    except:
        pass
    try:
        result = time.strptime(string, "%d/%m/%y")
    except:
        pass
    if result is not None:
        result = time.strftime('%Y-%m-%d', result)
    return result

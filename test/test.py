#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Tests for functions
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import argparse

from lib.Toolkit import toStringFormattedCPE, toOldCPE, pad

# parse command line arguments
argparser = argparse.ArgumentParser(description='Recursive test for functions')
argparser.add_argument('-v', action='store_true', help='Verbose')
args = argparser.parse_args()

def resultOf(original, result, expected):
  test={'in':original,'out':result,'expect':expected}
  test['passed'] = True if result==expected else False
  return test

def printResults(test, results):
  l = [x['passed'] for x in results]
  if False in l:
    print('[x] %s failed!'%test)
    if args.v:
      for x in [x for x in results if x['passed']==False]:
        print('    in:       %s'%x['in'])
        print('    out:      %s'%x['out'])
        print('    expected: %s'%x['expect'])
  else:
    print('[ ] %s passed'%test)

extend=[{'in':'cpe:/o:microsoft:windows_server_2008::sp2:itanium',                         'expect':'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium:-:-:-:-:-'},
        {'in':'cpe:/a:activehelper:activehelper_livehelp_live_chat:2.7.4::~~~wordpress~~', 'expect':'cpe:2.3:a:activehelper:activehelper_livehelp_live_chat:2.7.4:-:-:-:-:wordpress:-:-'},
        {'in':'cpe:/o:microsoft:windows:vista:sp1:x64-enterprise',                         'expect':'cpe:2.3:o:microsoft:windows:vista:sp1:x64-enterprise:-:-:-:-:-'},
        {'in':'cpe:/o:microsoft:windows-nt:vista::enterprise',                             'expect':'cpe:2.3:o:microsoft:windows-nt:vista:-:enterprise:-:-:-:-:-'},
        {'in':'cpe:/a:novell:iprint:5.90:-:~~~windows_vista~~',                            'expect':'cpe:2.3:a:novell:iprint:5.90:-:-:-:-:windows_vista:-:-'},
        {'in':'cpe:/o:linux:linux_kernel:-',                                               'expect':'cpe:2.3:o:linux:linux_kernel:-:-:-:-:-:-:-:-'},
        {'in':'cpe:/a:aokitaka:zip_with_pass_pro:6.3.4:-:~-~-~android~~',                  'expect':'cpe:2.3:a:aokitaka:zip_with_pass_pro:6.3.4:-:-:-:-:android:-:-'},
        {'in':'cpe:/a:7-zip:7-zip:4.65::~~~~x64~',                                         'expect':'cpe:2.3:a:7-zip:7-zip:4.65:-:-:-:-:-:x64:-'},
        {'in':'cpe:/a:acl:acl:9.1.0.213',                                                  'expect':'cpe:2.3:a:acl:acl:9.1.0.213:-:-:-:-:-:-:-'}]

trans=[{'in':'cpe:/o:microsoft:windows_server_2008::sp2:itanium',                         'expect':'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium'},
       {'in':'cpe:/a:activehelper:activehelper_livehelp_live_chat:2.7.4::~~~wordpress~~', 'expect':'cpe:2.3:a:activehelper:activehelper_livehelp_live_chat:2.7.4:-:-:-:-:wordpress'},
       {'in':'cpe:/o:microsoft:windows:vista:sp1:x64-enterprise',                         'expect':'cpe:2.3:o:microsoft:windows:vista:sp1:x64-enterprise'},
       {'in':'cpe:/o:microsoft:windows-nt:vista::enterprise',                             'expect':'cpe:2.3:o:microsoft:windows-nt:vista:-:enterprise'},
       {'in':'cpe:/a:novell:iprint:5.90:-:~~~windows_vista~~',                            'expect':'cpe:2.3:a:novell:iprint:5.90:-:-:-:-:windows_vista'},
       {'in':'cpe:/o:linux:linux_kernel:-',                                               'expect':'cpe:2.3:o:linux:linux_kernel'},
       {'in':'cpe:/a:aokitaka:zip_with_pass_pro:6.3.4:-:~-~-~android~~',                  'expect':'cpe:2.3:a:aokitaka:zip_with_pass_pro:6.3.4:-:-:-:-:android'},
       {'in':'cpe:/a:7-zip:7-zip:4.65::~~~~x64~',                                         'expect':'cpe:2.3:a:7-zip:7-zip:4.65:-:-:-:-:-:x64'},
       {'in':'cpe:/a:acl:acl:9.1.0.213',                                                  'expect':'cpe:2.3:a:acl:acl:9.1.0.213'}]

old =[{'in':'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium',                          'expect':'cpe:/o:microsoft:windows_server_2008::sp2:itanium'},
      {'in':'cpe:2.3:a:activehelper:activehelper_livehelp_live_chat:2.7.4:-:-:-:-:wordpress', 'expect':'cpe:/a:activehelper:activehelper_livehelp_live_chat:2.7.4::~~~wordpress~~'},
      {'in':'cpe:2.3:o:microsoft:windows:vista:sp1:x64-enterprise',                           'expect':'cpe:/o:microsoft:windows:vista:sp1:x64-enterprise'},
      {'in':'cpe:2.3:o:microsoft:windows-nt:vista:-:enterprise',                              'expect':'cpe:/o:microsoft:windows-nt:vista::enterprise'},
      {'in':'cpe:2.3:a:novell:iprint:5.90:-:-:-:-:windows_vista',                             'expect':'cpe:/a:novell:iprint:5.90::~~~windows_vista~~'},
      {'in':'cpe:2.3:o:linux:linux_kernel',                                                   'expect':'cpe:/o:linux:linux_kernel'},
      {'in':'cpe:2.3:a:aokitaka:zip_with_pass_pro:6.3.4:-:-:-:-:android',                     'expect':'cpe:/a:aokitaka:zip_with_pass_pro:6.3.4::~~~android~~'},
      {'in':'cpe:2.3:a:7-zip:7-zip:4.65:-:-:-:-:-:x64',                                       'expect':'cpe:/a:7-zip:7-zip:4.65::~~~~x64~'},
      {'in':'cpe:2.3:a:acl:acl:9.1.0.213',                                                    'expect':'cpe:/a:acl:acl:9.1.0.213'}]

pad1=[{'in':['a','b','c'],             'expect':['a','b','c',None,None]},
      {'in':['a','b','c','d','e'],     'expect':['a','b','c','d','e']},
      {'in':['a','b','c','d','e','f'], 'expect':['a','b','c','d','e','f']}]
padtext1=[{'in':['a','b','c'],             'expect':['a','b','c','-','-']},
          {'in':['a','b','c','d','e'],     'expect':['a','b','c','d','e']},
          {'in':['a','b','c','d','e','f'], 'expect':['a','b','c','d','e','f']}]
padtext2=[{'in':['a','b','c'],             'expect':['a','b','c','text','text']},
          {'in':['a','b','c','d','e'],     'expect':['a','b','c','d','e']},
          {'in':['a','b','c','d','e','f'], 'expect':['a','b','c','d','e','f']}]

result=[]
for x in extend:
  result.append(resultOf(x['in'],toStringFormattedCPE(x['in'],autofill=True),x['expect']))
printResults('Translate to 2.3 - success/autofill',result)

result=[]
for x in trans:
  result.append(resultOf(x['in'],toStringFormattedCPE(x['in']),x['expect']))
printResults('Translate to 2.3 - success/no autofill',result)

result=[]
for x in old:
  result.append(resultOf(x['in'],toOldCPE(x['in']),x['expect']))
printResults('Translate to 2.2 - success/no autofill',result)

result=[]
for x in pad1:
  result.append(resultOf(x['in'],pad(x['in'],5),x['expect']))
for x in padtext1:
  result.append(resultOf(x['in'],pad(x['in'],5,'-'),x['expect']))
for x in padtext2:
  result.append(resultOf(x['in'],pad(x['in'],5,'text'),x['expect']))
printResults('Padding lists    - empty, char and text - ',result)


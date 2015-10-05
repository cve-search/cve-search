#!/usr/bin/env python3
#
# cve_doc converts CVE to asciidoc
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2015       Alexandre Dulaunoy - a@foo.be


import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import json
import re

from optparse import OptionParser

from lib.Query import lastentries, apigetcve, apibrowse, apisearch

optp = OptionParser()
optp.add_option('-c', '--cve', dest='cve', default='CVE-2015-0001', help='CVE id to convert')
optp.add_option('-f', '--format', dest='format', default='asciidoc', help='output format : asciidoc')
optp.add_option('-a', '--api', dest='api', default='http://cve.circl.lu/', help='HTTP API url (default: http://cve.circl.lu)')
(opts, args) = optp.parse_args()


cve = json.loads(apigetcve(opts.api, cveid=opts.cve))

if not cve:
    sys.exit(10)

print ("= Common Vulnerabilities and Exposures - {}".format(cve['id']))
print ("cve-search <{}/cve/{}>".format(opts.api,cve['id']))
print ("{},{}".format(cve['id'],cve['Modified']))
print (":toc:")
print ("== {} Summary".format(cve['id']))
print ("\n"+cve['summary'])

print ("\n== Vulnerable configurations\n")
for vul in cve['vulnerable_configuration']:
    print ("* {}".format(re.sub(r'\n', '-', vul['title'])))
if cve['cvss']:
    print ("\n== Common Vulnerability Scoring System")
    print ("CVSS value:: {}".format(cve['cvss']))
if cve['impact']:
    print ("\n== Impact Metrics")
    print ("\n[cols=\"1,2\"]")
    print ("|===")
    types = ['availability', 'confidentiality', 'integrity']
    for t in types:
        print ("|{}".format(t.title()))
        print ("|{}".format(cve['impact'][t]))
    print ("|===")
if cve['access']:
    print ("\n== Access to the vulnerability")
    print ("\n[cols=\"1,2\"]")
    print ("|===")
    types = ['authentication', 'complexity', 'vector']
    for t in types:
        print ("|{}".format(t.title()))
        print ("|{}".format(cve['access'][t]))
    print ("|===")
if cve['references']:
    print ("\n== References")
if len(cve['references']) > 1:
    for ref in cve['references']:
        print ("* {}".format(ref))
elif len(cve['references']) == 1:
    ref = cve['references'][0]
    print ("* {}".format(ref))

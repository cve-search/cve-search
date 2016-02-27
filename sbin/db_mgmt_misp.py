#!/usr/bin/env python3
#
# Import script of MISP info.
#
# Imported in cvedb in the collection named user_misp.
#

# Imports
import os
import sys
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

import dateutil.parser
import math
import pytz
from datetime import datetime
from pymisp import PyMISP

from lib.ProgressBar import progressbar
from lib.Config import Configuration as conf
import lib.DatabaseLayer as db

i = db.getLastModified('user_misp')
now = datetime.utcnow().replace(tzinfo = pytz.utc)
if i: 
    last  = dateutil.parser.parse(i)
    delta = now - last
    since = "%sm"%math.ceil(delta.total_seconds()/60)
else: since=""

# Misp interface
misp_url, misp_key = conf.getMISPCredentials()
if not misp_url:
    print("MISP credentials not specified")
    sys.exit(1)
try:
    misp = PyMISP(misp_url, misp_key, True, 'json')
except:
    print("Failed to connect to MISP. Wrong URL?")
    sys.exit(1)

# Fetch data
misp_last = misp.download_last(since)

# Check data
if 'message' in misp_last.keys():
    if misp_last['message'] == 'No matches':
        sys.exit(0)
    elif misp_last['message'].startswith('Authentication failed.'):
        print("MISP Authentication failed")
        sys.exit(1)
if not 'response' in misp_last:
    print("Error occured while fetching MISP data")
    sys.exit(1)

bulk =[]
for entry in progressbar(misp_last['response']):
    # Get info
    event=entry['Event']
    attrs=event['Attribute']
    CVEs=   [x['value'] for x in attrs if x['type'] == 'vulnerability']
    if len(CVEs) == 0: continue
    threats=    [x['value'] for x in attrs if x['category'] == 'Attribution'       and x['type'] == 'threat-actor']
    tags   =    [x['value'] for x in attrs if x['category'] == 'Other'             and x['type'] == 'text']
    tags.extend([x['value'] for x in attrs if x['category'] == 'External analysis' and x['type'] == 'text'])
    # Add info to each CVE
    for cve in CVEs:
        item={'id':cve}
        if len(threats) !=0: item['threats'] = threats
        if len(tags)    !=0: item['tags'] = tags
        if len(item.keys())>1: bulk.append(item) # Avoid empty collections
db.bulkUpdate("user_misp", bulk)

#update database info after successful program-run
db.setColUpdate('user_misp', now.strftime("%a, %d %h %Y %H:%M:%S %Z"))

#
#
# Updater script of CVE/CPE database
#

import pymongo
import shlex, subprocess
import syslog
import argparse
import time

sources = [{'name': "cpe", 'updater': "python3 db_mgmt_cpe_dictionnary.py"},{'name': "cves", 'updater': "python3 db_mgmt.py -u"},{'name': 'vfeed', 'updater': "python3 db_mgmt_vfeed.py"} , {'name': 'vendor', 'updater': "python3 db_mgmt_vendorstatements.py"}, {'name': 'cwe', 'updater': "python3 db_mgmt_cwe.py"}, {'name': 'redis-cache-cpe', 'updater': 'python3 db_cpe_browser.py'}] 

argParser = argparse.ArgumentParser(description='Database updater for cve-search')
argParser.add_argument('-v', action='store_true', help='Logging on stdout (default is syslog)')
argParser.add_argument('-l', action='store_true', help='Running at regular interval', default=False)
argParser.add_argument('-i', action='store_true', help='Indexing new cves entries in the fulltext indexer', default=False)
argParser.add_argument('-c', action='store_true', help='Enable CPE redis cache', default=False)

args = argParser.parse_args()

def nbelement(db = "cvedb", collection = None):
    if collection is None:
        collection = "cves"
    connect = pymongo.Connection()
    c = connect[db]
    return c[collection].count()

def logging(message = None):
    if args.v:
        print (message)
    else:
        syslog.syslog(message)

loop = True
while (loop):
    if not args.l:
        loop = False
    newelement = 0
    for source in sources:
        if source['name'] is not "redis-cache-cpe":
            message = 'Starting ' + source['name']
            logging(message)
            before = nbelement(collection = source['name'])
            subprocess.Popen((shlex.split(source['updater']))).wait()
            after = nbelement(collection = source['name'])
            message = source['name'] + " has " + str(after) + " elements (" + str(after-before)+ " update)"
            newelement = str(after-before)
            logging(message)
        elif (args.c is True and source['name'] is "redis-cache-cpe"):
            message = 'Starting ' + source['name']
            logging(message)
            subprocess.Popen((shlex.split(source['updater']))).wait()
            message = source['name'] + " updated"
            logging(message)
    if args.i and int(newelement) > 0:
        subprocess.Popen((shlex.split("python3 db_fulltext.py -v -l"+newelement))).wait
    if args.l is not False:
        time.sleep(3600)

#!/usr/bin/env python3
# coding=utf-8

import os
import sys
import xlrd, datetime
import shutil
runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, ".."))

from lib.Config import Configuration
import lib.DatabaseLayer as dbLayer

bulletinurl = "https://technet.microsoft.com/library/security/"

def minimalist_xldate_as_datetime(xldate, datemode):
    # datemode: 0 for 1900-based, 1 for 1904-based
    return (
        datetime.datetime(1899, 12, 30)
        + datetime.timedelta(days=xldate + 1462 * datemode)
        )

# dictionary
msbulletinurl = Configuration.getMSBULLETINDict()
tmppath = Configuration.getTmpdir()

try:
    f = Configuration.getFile(msbulletinurl)
except:
    sys.exit("Cannot open url %s. Bad URL or not connected to the internet?"%(msbulletinurl))

# check modification date
i=dbLayer.getInfo("ms")
if i is not None:
    if f.headers['last-modified'] == i['last-modified']:
        print("Not modified")
        sys.exit(0)

if not os.path.exists(tmppath):
    os.mkdir(tmppath)
with open(tmppath+'/BulletinSearch.xlsx', 'wb') as fp:
    shutil.copyfileobj(f, fp)
fp.close()
     
# parse xlsx and store in database
wb = xlrd.open_workbook(tmppath+'/BulletinSearch.xlsx')
sh = wb.sheet_by_name('Bulletin Search')
header = [s.replace('\n', ' ') for s in sh.row_values(0)]
bulletin = {}
software = {}
prev_id = ""

for rownum in range(sh.nrows-1):    
    row =  sh.row_values(rownum + 1)
    if row[1] == prev_id:
        software = {}
        software['product'] = row[6]
        software['KB'] = str(row[7]).strip('.0')
        software['component'] = row[8]
        software['impact'] = row[9]
        software['severity'] = row[10]        
        software['replace_id'] = row[11][:8]
        software['replace_bk'] = row[11][9:-1]
        software['reeboot'] = row[12]
        bulletin['software'].append(software)
    else:
        if bulletin :
            dbLayer.updateMSBulletin(bulletin)
        bulletin = {}
        software = {}
        bulletin['Published'] = minimalist_xldate_as_datetime(row[0], 0).isoformat()
        bulletin['id'] = row[1]
        bulletin['KB'] = str(row[2]).strip('.0')
        bulletin['severity'] = row[3]
        bulletin['impact'] = row[4]
        bulletin['title'] = row[5]
        software['product'] = row[6]
        software['KB'] = str(row[7]).strip('.0')
        software['component'] = row[8]
        software['impact'] = row[9]
        software['severity'] = row[10]
        software['replace_id'] = row[11][:8]
        software['replace_bk'] = row[11][9:-1]
        software['reeboot'] = row[12]
        bulletin['CVE'] = row[13].split(',')
        bulletin['software'] = [software]
        bulletin['url'] = bulletinurl + row[1].lower()
        
        prev_id = row[1]

#update database info after successful program-run
dbLayer.setColUpdate('ms', f.headers['last-modified'])
# shutil.rmtree('./tmp')





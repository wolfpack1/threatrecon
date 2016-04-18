
"""
Copyright (C) 2016 by Wapack Labs Corporation
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
#This program pulls daily data from Threat Recon and dumps to a CSV or JSON file. This is only for feed users. For more information on the threat recon feed, contact threatrecon@wapacklabs.com 


import sys
from urllib2 import urlopen, quote
import urllib2
import datetime
from datetime import date, timedelta
import json
import csv
import time


api_key = 'YourAPIKeyHere'

def query_threat_recon(date, api_key):
    #proxy = urllib2.ProxyHandler({'https': 'username:password@proxy_host:proxy_port'}) #comment if no proxy, or proxy does not require authentication
    proxy = urllib2.ProxyHandler({'https': 'proxy_host:proxy_port'}) #comment if no proxy, or proxy requires authentication
    opener = urllib2.build_opener(proxy) #comment if no proxy
    urllib2.install_opener(opener) #comment if no proxy
    url = "https://api.threatrecon.co/api/v1/search/date?date="+date+"&api_key="+api_key
    print url
    f = urllib2.urlopen(url)
    data = json.load(f)
    results = data["Results"]

    return results

yesterday = date.today() - timedelta(1)

date = yesterday.strftime("%Y-%m-%d")

dates = date.split()

#dates = ['2016-04-11'] #uncomment this line and add multiple dates to this list if you want to download multiple days worth of data

for date in dates:
    csv_file_name = 'TR_DAILY_EXPORT_'+date+'.csv'

    jsonfile_filename = 'JSON_DAILY_EXPORT_'+date+'.json'

    jsonfile = open(jsonfile_filename, 'w')


    with open(csv_file_name, 'wb') as csvfile:
        indicatorwriter = csv.writer(csvfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
        indicatorwriter.writerow(['INDICATOR','REFERENCE','SOURCE','KILLCHAIN','FIRST_SEEN','LAST_SEEN','ATTRIBUTION','PROCESS_TYPE','RNAME', 'RDATA','ROOT_NODE','COUNTRY','TAGS','COMMENT','CONFIDENCE'])

        print 'Downloading Threat Recon data for '+date+' ...'

        while True:
            try:                
                results = query_threat_recon(date, api_key)
                print 'success!'
                break
            except:
                print 'Please wait ..'
                time.sleep(60)
                try:
                    results = query_threat_recon(date, api_key)
                    print 'success!'
                    break
                except:
                    continue
        
        if results == None:
            print 'no results'
            pass
        if results != None:
            for item in results:
                print item

                try:
                    indicator = str(item["Indicator"]).decode('utf-8')
                    reference = str(item["Reference"]).decode('utf-8')
                    source = str(item["Source"]).decode('utf-8')
                    killchain = str(item["KillChain"]).decode('utf-8')
                    first_seen = str(item["FirstSeen"]).decode('utf-8')
                    last_seen = str(item["LastSeen"]).decode('utf-8')
                    attribution = str(item["Attribution"]).decode('utf-8')
                    process_type = str(item["ProcessType"]).decode('utf-8')
                    rrname = str(item["Rrname"])
                    rdata = str(item["Rdata"])
                    rootnode = str(item["RootNode"])
                    country = str(item["Country"]).decode('utf-8')
                    tags = str(item["Tags"]).decode('utf-8')
                    comment = item["Comment"].decode('utf-8')
                    confidence = str(item["Confidence"]).decode('utf-8')
                    indicatorwriter.writerow([indicator,reference,source,killchain,first_seen,last_seen,attribution,
                                              process_type,rrname,rdata,rootnode,country,tags,comment,confidence])

                    json.dump(item, jsonfile)
                    jsonfile.write('\n')
                except:
                    raise
                    continue
                

        print 'downloaded results to '+ csv_file_name
        print 'downloaded results to '+ jsonfile_filename
        jsonfile.close()
 

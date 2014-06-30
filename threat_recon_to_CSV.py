

import urllib
from urllib2 import urlopen, quote
import urllib2
import json
import time
import datetime
import csv
import unicodedata

timestring = time.time()
formatted_timestring = datetime.datetime.fromtimestamp(timestring).strftime('%Y_%m_%d')

search = raw_input("Please Enter an indicator: ")

api_key = 'my API key'

def query_threat_recon(indicator, api_key):
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    f = urllib2.urlopen("https://api.threatrecon.co:8080/api/v1/search", params)
    data = json.load(f)
    results = data["Results"]
    #print json.dumps(data, indent=4, sort_keys=False)    
    return results

results = query_threat_recon(search, api_key)


csv_file_name = 'TR_search_'+search+'_'+formatted_timestring+'.csv'
                 
with open(csv_file_name, 'wb') as csvfile:
    indicatorwriter = csv.writer(csvfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
    indicatorwriter.writerow(['INDICATOR','REFERENCE','SOURCE','KILLCHAIN','FIRST_SEEN','LAST_SEEN','ATTRIBUTION','PROCESS_TYPE','RNAME', 'RDATA','ROOT_NODE','COUNTRY','TAGS','COMMENT','CONFIDENCE'])
    for item in results:
        indicator = search
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
        comment = item["Comment"]
        comment2 = unicodedata.normalize('NFKD', comment).encode('ascii','ignore')
        confidence = str(item["Confidence"]).decode('utf-8')
        indicatorwriter.writerow([indicator,reference,source,killchain,first_seen,last_seen,attribution,process_type,rrname,rdata,rootnode,country,tags,comment2,confidence])                      

lenresults = str(len(results))

print lenresults +' records added to CSV'

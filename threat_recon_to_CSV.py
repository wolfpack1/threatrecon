"""
INSTRUCTIONS:
Add your IP key to api_key variable. Example:

api_key = '95aaa9d3701d6aa20d2c5a2c8a0486c7'

Run from the command line with the search as the argument. Example:

C:\Python27>python threat_recon_to_CSV.py ns1.afraid.org

"""


import urllib
import urllib2
import ssl
import json
import re
import sys
import socket
import httplib
import csv
import datetime
import time
import unicodedata

timestring = time.time()
formatted_timestring = datetime.datetime.fromtimestamp(timestring).strftime('%Y_%m_%d')

api_key = 'my API key'

# from http://bugs.python.org/issue11220
class HTTPSConnectionV3(httplib.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        httplib.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        try:
            self.sock = ssl.wrap_socket(
                sock,
                self.key_file,
                self.cert_file,
                ssl_version=ssl.PROTOCOL_SSLv3
            )
        except ssl.SSLError, e:
            print("Trying SSLv3.")
            self.sock = ssl.wrap_socket(
                sock,
                self.key_file,
                self.cert_file,
                ssl_version=ssl.PROTOCOL_SSLv23
            )


class HTTPSHandlerV3(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(HTTPSConnectionV3, req)



def query_threat_recon(indicator, api_key):
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    urllib2.install_opener(urllib2.build_opener(HTTPSHandlerV3()))

    f = urllib2.urlopen("https://api.threatrecon.co/api/v1/search", params)
    data = json.load(f)
    results = data["Results"]
    #print json.dumps(data, indent=4, sort_keys=False)
    return results


if __name__ == "__main__":
    try:
        search = sys.argv[1]
        #search = search
        print "searching with %s" % search
    except:
        print "need argument"
        exit(1)

    results = query_threat_recon(search, api_key)
    csv_file_name = 'TR_search_'+formatted_timestring+'.csv'

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




    exit(0)

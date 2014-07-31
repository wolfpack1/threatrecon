import urllib
import urllib2
from urllib2 import urlopen, quote
import json
import re,sys
import socket


search = 'serval.essanavy.com'

api_key = 'my API key'

def search_is_domain(strg, search=re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", re.I).search):
    return bool(search(strg))

def query_threat_recon(indicator, api_key):
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    f = urllib2.urlopen("https://api.threatrecon.co/api/v1/search", params)
    data = json.load(f)
    results = data["Results"]
    print json.dumps(data, indent=4, sort_keys=False)    
    return results

results = query_threat_recon(search, api_key)

#check host IP if no results
if results == None:
    if search_is_domain(search):
        try: # tries to get IP from domain
            iplookup = socket.gethostbyname(search)
            print '\n'
            print '*****No results found for this domain... checking host IP:'+iplookup
            print '\n'
            results = query_threat_recon(iplookup, api_key)
        except:
            iplookup = 'no joy'

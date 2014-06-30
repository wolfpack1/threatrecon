import urllib
import urllib2
from urllib2 import urlopen, quote
import json

search = 'serval.essanavy.com'

api_key = 'my API key'

def query_threat_recon(indicator, api_key):
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    f = urllib2.urlopen("https://api.threatrecon.co:8080/api/v1/search", params)
    data = json.load(f)
    results = data["Results"]
    print json.dumps(data, indent=4, sort_keys=False)    
    return results

results = query_threat_recon(search, api_key)

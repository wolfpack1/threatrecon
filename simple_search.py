#!/usr/bin/env python
import urllib
import urllib2
import json
import re
import sys
import socket
from sslv3 import HTTPSHandlerV3


search = 'serval.essanavy.com'

api_key = 'my API key'


def search_is_domain(
    strg,
    search=re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", re.I).search
):
    return bool(search(strg))


def query_threat_recon(indicator, api_key):
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    urllib2.install_opener(urllib2.build_opener(HTTPSHandlerV3()))

    f = urllib2.urlopen("https://api.threatrecon.co/api/v1/search", params)
    data = json.load(f)
    results = data["Results"]
    print json.dumps(data, indent=4, sort_keys=False)
    return results


if __name__ == "__main__":
    try:
        search = sys.argv[1]
        print "searching with %s" % search
    except:
        print "need argument"
        exit(1)

    results = query_threat_recon(search, api_key)

    #check host IP if no results
    if results is None:
        if search_is_domain(search):
            try:    # tries to get IP from domain
                iplookup = socket.gethostbyname(search)
                print
                print("\n*****No results found for this domain...")
                print ("checking host IP: %s\n" % iplookup)
                results = query_threat_recon(iplookup, api_key)
            except:
                iplookup = 'no joy'
    exit(0)

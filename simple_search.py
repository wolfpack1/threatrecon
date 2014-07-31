#!/usr/bin/env python
import urllib
import urllib2
import ssl
import json
import re
import sys
import socket
import httplib


search = 'serval.essanavy.com'

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

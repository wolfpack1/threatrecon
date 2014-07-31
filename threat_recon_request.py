
"""
INSTRUCTIONS:
Add your IP key to api_key variable. Example:

api_key = '95aaa9d3701d6aa20d2c5a2c8a0486c7'

Run from the command line with the search as the argument. Example:

C:\Python27>python threat_recon_request.py serval.essanavy.com

"""



import urllib
import urllib2
import ssl
import json
import re
import sys
import socket
import httplib



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
    indicator_meta = []
    related_indicators = []
    #check host IP if no results
    if results is None:
        if search_is_domain(search):
            try: # tries to get IP from domain
                iplookup = socket.gethostbyname(search)
                print
                print("\n*****No results found for this domain...")
                print ("checking host IP: %s\n" % iplookup)
                results = query_threat_recon(iplookup, api_key)
            except:
                pass

#find relationships in JSON results and list out
    if results != None:
        for item in results:
            root_node = item["RootNode"]
            rdata = item["Rdata"]
            indicator = item["Indicator"]
            if item["RootNode"] == '' and search == item["Indicator"]:
                indicator_meta.append([item["Reference"],
                                       item["Source"],
                                       item["KillChain"],
                                       item["FirstSeen"],
                                       item["LastSeen"],
                                       item["Attribution"],
                                       item["ProcessType"],
                                       item["Country"],
                                       item["Tags"],
                                       item["Comment"],
                                       str(item["Confidence"])
                                       ])
            if search == item["RootNode"]:
                related_indicators.append([item["Indicator"],
                                           item["ProcessType"],
                                           item["Rdata"],
                                           item["Rrname"],
                                           item["RootNode"]
                                            ])
            if item["RootNode"] != '' and search != item["RootNode"]:
                related_indicators.append([item["Indicator"],
                                           item["ProcessType"],
                                           item["Rdata"],
                                           item["Rrname"],
                                           item["RootNode"]]
                                           )


#check to see if search is a derived indicator
    if len(indicator_meta) == 0 and len(related_indicators) != 0:
        print "COMMENT: "+search+" is a derived indicator...metadata is inherited from the root node"

    try:
        list_meta = indicator_meta[0]
    except:
        list_meta = []

    if len(list_meta) == 0 and len(related_indicators) == 0:
        print 'sorry, no results.. that might be a good thing'

#list metadata if Direct indicator
    if len(list_meta) != 0:
        print "Threat Recon has found the following metadata on "+search+" \n"
        for item in indicator_meta:
            if len(item[0]) != 0:
                print 'Reference:'+item[0]
            if len(item[1]) != 0:
                print 'Source:'+item[1]
            if len(item[2]) != 0 and item[2] != 'NA':
                print 'KillChain:'+item[2]
            if len(item[3]) != 0 and item[3] != 'UNK':
                print 'First Seen:'+item[3]
            if len(item[4]) != 0 and item[3] != 'UNK':
                print 'Last Seen:'+item[4]
            if len(item[5]) != 0:
                print 'Attribution:'+item[5]
            if len(item[6]) != 0:
                print 'ProcessType:'+item[6]
            if len(item[7]) != 0:
                print 'Country:'+item[7]
            if len(item[8]) != 0:
                print 'TAGS: '+item[8]
            if len(item[9]) != 0:
                print 'Comment: '+item[9]
            if len(item[10]) != 0:
                print 'Confidence '+item[10]
            print '\n'


#list related indicators
    if len(related_indicators) != 0:
        print "\n"
        print "Threat Recon has found the following indicator(s) that are related to "+search+" \n"
        for item in related_indicators:
            if item[0] != search:
                print '******************'
                print 'Related indicator:'+ item[0]
                print 'Relationship type:'+ item[1]
                if len(item[2]) != 0:
                    print 'Relationship pivot:'+item[2]
                if len(item[3]) != 0 and item[3] != item[0]:
                    print 'RRNAME:'+item[3]
                print '****************** \n'
            else:
                print '******************'
                print 'Related indicator:'+ item[4]
                print 'Relationship type:'+ item[1]
                if len(item[2]) != 0:
                    print 'Relationship pivot:'+item[2]
                if len(item[3]) != 0 and item[3] != item[4]:
                    print 'RRNAME:'+item[3]
                print '****************** \n'





        
    exit(0)

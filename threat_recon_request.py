"""
instructions:
copy sslv3.py module to Python directory

replace api_key = 'my API key' with your API key
example:

api_key = '3f3e9492b7d5190cf9345a15fab8ebe2'

"""

import urllib
# from urllib2 import urlopen
# from urllib2 import quote
import urllib2
import json
import socket
import re
from sslv3 import HTTPSHandlerV3


search = raw_input("Please Enter an indicator: ")

api_key = 'my API key'


def search_is_domain(
    strg,
    search=re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$",
        re.I
    ).search
):
        return bool(search(strg))


def query_threat_recon(indicator, api_key):
    params = urllib.urlencode(
        {'api_key': api_key, 'indicator': indicator}
    )
    urllib2.install_opener(urllib2.build_opener(HTTPSHandlerV3()))
    f = urllib2.urlopen(
        "https://api.threatrecon.co/api/v1/search",
        params
    )
    data = json.load(f)
    results = data["Results"]
    #print json.dumps(data, indent=4, sort_keys=False)
    return results

results = query_threat_recon(search, api_key)

indicator_meta = []
related_indicators = []


#check host IP if no results
if results is None:
    if search_is_domain(search):
        try:    # tries to get IP from domain
            iplookup = socket.gethostbyname(search)
            print ("\n*****No results found for this domain...")
            print("checking host IP: %s\n" % iplookup)
            results = query_threat_recon(iplookup, api_key)
        except:
            iplookup = 'no joy'

#find relationships in JSON results and list out
else:
    for item in results:
        root_node = item["RootNode"]
        rdata = item["Rdata"]
        indicator = item["Indicator"]
        if item["RootNode"] == '' and search == item["Indicator"]:
            indicator_meta.append(
                [
                    item["Reference"],
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
                ]
            )
        if search == item["RootNode"]:
            related_indicators.append(
                [
                    item["Indicator"],
                    item["ProcessType"],
                    item["Rdata"],
                    item["Rrname"],
                    item["RootNode"]
                ]
            )
        if item["RootNode"] != '' and search != item["RootNode"]:
            related_indicators.append(
                [
                    item["Indicator"],
                    item["ProcessType"],
                    item["Rdata"],
                    item["Rrname"],
                    item["RootNode"]
                ]
            )


#check to see if search is a derived indicator
if len(indicator_meta) == 0 and len(related_indicators) != 0:
    print "COMMENT: %s is a derived indicator..." % search
    print "metadata is inherited from the root node"

try:
    list_meta = indicator_meta[0]
except:
    list_meta = []

if len(list_meta) == 0 and len(related_indicators) == 0:
    print 'sorry, no results.. that might be a good thing'

#list metadata if Direct indicator
if len(list_meta) != 0:
    print "Threat Recon has found the following metadata on "+search+" \n"
    tags = [
        'Reference',
        'Source',
        'KillChain',
        'First Seen',
        'Last Seen',
        'Attribution',
        'ProcessType',
        'Country',
        'TAGS',
        'Comment',
        'Confidence'
    ]
    for item in indicator_meta:
        for i in range(11):
            if len(item[i]) != 0:
                print "%s: %s" % (tags[i], item[i])
        print '\n'

#list related indicators
if len(related_indicators) != 0:
        print "\n"
        print "Threat Recon has found the following indicator(s) "
        print "that are related to %s\n" % search
        for item in related_indicators:
            if item[0] != search:
                print '******************'
                print 'Related indicator: %s' % item[0]
                print 'Relationship type: %s' % item[1]
                if len(item[2]) != 0:
                        print 'Relationship pivot: %s' % item[2]
                if len(item[3]) != 0 and item[3] != item[0]:
                        print 'RRNAME: %s' % item[3]
                print '****************** \n'
            else:
                print '******************'
                print 'Related indicator: %s' % item[4]
                print 'Relationship type: %s' % item[1]
                if len(item[2]) != 0:
                        print 'Relationship pivot: %s' % item[2]
                if len(item[3]) != 0 and item[3] != item[4]:
                        print 'RRNAME: %s' % item[3]
                print '****************** \n'

"""
Copyright (C) 2014 by Wapack Labs Corporation
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


import socket
from threatrecon.api import get_api_key
from threatrecon.query import raw_query_threat_recon


api_key = get_api_key() or 'my api key'
search = raw_input("Please Enter an indicator: ")

results = raw_query_threat_recon(search, api_key)

indicator_meta = []
related_indicators = []


#check host IP if no results
if not results:     # results is an empty list
    try:    # tries to get IP from domain
        iplookup = socket.gethostbyname(search)
        print "***** No results found for this domain..."
        print "***** checking host IP: %s\n" % iplookup
        results = raw_query_threat_recon(iplookup, api_key)
    except socket.gaierror as e:
        print "***** Lookup failed: %s" % e

#find relationships in JSON results and list out
else:
    for item in results:
        root_node = item["rootnode"]
        rdata = item["rdata"]
        indicator = item["indicator"]
        if item["rootnode"] == '' and search == item["indicator"]:
            indicator_meta.append(
                [
                    item["reference"],
                    item["source"],
                    item["killchain"],
                    item["firstseen"],
                    item["lastseen"],
                    item["attribution"],
                    item["processtype"],
                    item["country"],
                    item["tags"],
                    item["comment"],
                    str(item["confidence"])
                ]
            )
        if search == item["rootnode"]:
            related_indicators.append(
                [
                    item["indicator"],
                    item["processtype"],
                    item["rdata"],
                    item["rrname"],
                    item["rootnode"]
                ]
            )
        if item["rootnode"] != '' and search != item["rootnode"]:
            related_indicators.append(
                [
                    item["indicator"],
                    item["processtype"],
                    item["rdata"],
                    item["rrname"],
                    item["rootnode"]
                ]
            )


#check to see if search is a derived indicator
if not indicator_meta and related_indicators:
    print "COMMENT: %s is a derived indicator..." % search
    print "metadata is inherited from the root node"

if indicator_meta:
    list_meta = indicator_meta[0]
else:
    list_meta = []

if not list_meta and not related_indicators:
    print 'sorry, no results.. that might be a good thing'

#list metadata if Direct indicator
if list_meta:
    print "Threat Recon has found the following metadata on %s: " % search
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
            if item[i]:
                print "%s: %s" % (tags[i], item[i])
        print '\n'

#list related indicators
if related_indicators:
        print "\n"
        print "Threat Recon has found the following indicator(s) "
        print "that are related to %s" % search
        for item in related_indicators:
            if item[0] != search:
                print '******************'
                print 'Related indicator: %s' % item[0]
                print 'Relationship type: %s' % item[1]
                if item[2]:
                        print 'Relationship pivot: %s' % item[2]
                if item[3] and item[3] != item[0]:
                        print 'RRNAME: %s' % item[3]
                print '****************** \n'
            else:
                print '******************'
                print 'Related indicator: %s' % item[4]
                print 'Relationship type: %s' % item[1]
                if item[2]:
                        print 'Relationship pivot: %s' % item[2]
                if item[3] and item[3] != item[4]:
                        print 'RRNAME: %s' % item[3]
                print '****************** \n'

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

import re,sys
import socket
import urllib
import sys
import hashlib
from urllib import urlopen, quote
import unicodedata
import codecs
from collections import Counter
from igraph import *
import cairo
import time
import datetime
import json


"""
sample searches
indicator = '9arsana.no-ip.biz'
indicator = 'blogs.msdnblog.com'
indicator = 'koko.myftp.org'
indicator = 'games.servecounterstrike.com'
indicator = '14.102.248.11'
"""

i = raw_input("Please Enter an Indicator: ")
ss = i.strip()
indicator = (ss.lower())

api_key = 'my API key'



def search_is_domain(strg, search=re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", re.I).search):
    return bool(search(strg))

def search_is_IP(strg, search=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", re.I).search):
    return bool(search(strg))

def query_threat_recon(indicator, api_key):
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    f = urllib.urlopen("https://api.threatrecon.co/api/v1/search", params)
    data = json.load(f)
    results = data["Results"]
    return results

results = query_threat_recon(indicator, api_key)

#create filename for SVG graph
timestring = time.time()
formated_timestring = datetime.datetime.fromtimestamp(timestring).strftime('%Y_%m_%d')
graphname = indicator +'_'+formated_timestring+'.svg'


relationships = []
node_list = []

master_list2 = []
master_rel2 = []

#create vertices component
def createvert(str1):
    a = len(str1)
    stra = list(xrange(a))
    Vertices = {}
    k = 0
    for eng in str1:
        Vertices[eng] = stra[k]
        k += 1
    return Vertices


#get graph nodes
def get_nodes_list(results):
    if results != None:
        for item in results:
            root_node = item["RootNode"]
            rdata = item["Rdata"]
            indicator = item["Indicator"]
            if len(root_node) != 0:
                node_list.append(root_node)
            if len(rdata) != 0:
                node_list.append(rdata)
            node_list.append(indicator)
        return node_list

#find relationship pairs in JSON results and write to array
def get_nodes_rels(results):
    if results != None:
        for item in results:
            root_node = item["RootNode"]
            #print root_node
            rdata = item["Rdata"]
            #print rdata
            indicator = item["Indicator"]
            if len(root_node) != 0:
                #print root_node
                if len(rdata) == 0:
                    relationships.append([root_node,indicator])
                else:
                    relationships.append([root_node,rdata])
                    relationships.append([indicator,rdata])
            if item["ProcessType"] == 'Derived_subdomain':
                relationships.append([root_node,indicator])
        return relationships


#get nodes and relationships if they exist
if results != None:
    list1 = get_nodes_list(results)
    rels1 = get_nodes_rels(results)
    #print node_list




#checks to see if graph is small, and then does a recursive search on root node to build out results
if len(results) < 3:
    root_nodes = []
    list2 = []
    rels2 = []
    for item in results:
        root_node = item["RootNode"]
        if len(root_node) != 0:
            root_nodes.append(root_node[0])
            results = query_threat_recon(root_node, api_key)
            list2 = get_nodes_list(results)
            rels2 = get_nodes_rels(results)
            if list2 != None:
                for items in list2:
                    master_list2.append(items)
            if rels2 != None:
                for items in rels2:
                    master_rel2.append(items)
            print 'searching on indicator root node'
            break


get_all_nodes = master_list2 + list1
all_relationships = master_rel2 + rels1
node_list_set = list(set(get_all_nodes))

#create graph vertices
a = createvert(node_list_set)

#get the edges
edges = [(a[v1], a[v2]) for v1,v2 in all_relationships]

#remove any duplicates
set(tuple(element) for element in edges)

#turn back into list for processing
edges_new = [list(t) for t in set(tuple(element) for element in edges)]

def createGraph(s, edges, Vertices, graphname):
    dic_to_list = []
    a = Vertices.items()
    ipDomainColor = []
    for k, v in a:
        dic_to_list.append([v, k])
    srted = sorted(dic_to_list)
    IPval = []
    for k, v in srted:
        if s == v:
            nodevalue = k
        if search_is_IP(v):
            IPval.append(k)
    writeNewV = []
    for k, v in srted:
        writeNewV.append(v)
    srtededg = sorted(edges)
    for item in writeNewV:
        if item == s:
            ipDomainColor.append('start_node')
        elif search_is_domain(item):
            ipDomainColor.append('domain')
        elif search_is_IP(item):
            ipDomainColor.append('ip')
    f = Graph(srtededg)
    f.vs["indicator"] = writeNewV
    f.vs["label"] = f.vs["indicator"]
    f.vs["type1"] = ipDomainColor
    color_dict = {"start_node": "yellow", "domain": "red", "ip": "grey"}
    f.vs["color"] = [color_dict[type1] for type1 in f.vs["type1"]]
    layout = f.layout("fr")    
    if len(edges) >= 200:        
        plot(f, graphname, layout = layout, bbox = (3500, 3500), margin = 100)
        print '\n'
        print 'created igraph file:'+graphname
    else:      
        plot(f, graphname, layout = layout, bbox = (2000, 2000), margin = 100)
        print '\n'
        print 'created igraph file:'+graphname
        
createGraph(indicator, edges_new, a, graphname)



                 


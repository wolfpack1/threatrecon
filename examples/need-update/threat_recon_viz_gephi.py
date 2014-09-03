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
from gexf import *
from collections import Counter
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


def create_gexf (s, Vertices, edges):
    gexf = Gexf("Paul Girard","A hello world! file")
    graph=gexf.addGraph("force-directed","dynamic","Threat Recon Relationships graph")
    dic_to_list = []
    a = Vertices.items()
    for k, v in a:
        dic_to_list.append([v, k])
    srted = sorted(dic_to_list)
    srtededg = sorted(edges)
    ipvals = []
    for k, v in srted:
        if s == v:
            nodevalue = k
    for k, v in srted:
        ks = str(k)
        ksn = '"'+ks+'"'
        vn = '"'+v+'"'
        graph.addNode(ksn,vn)
        n=graph.addNode(ksn,vn)
        if v == s:
            r='0'
            g='0'
            b='204'
            n.setColor(r, g, b)
        elif search_is_domain(v):
            r='76'
            g='0'
            b='153'
            n.setColor(r, g, b)
        elif search_is_IP(v):
            r='255'
            g='153'
            b='51'
            n.setColor(r, g, b)
    count = 0
    incominglinklist = []
    for k, v in srtededg:
        incominglinklist.append(v)
    incominglinklistCount = Counter(incominglinklist)
    incominglinklistCount_list = incominglinklistCount.items()
    networkednodes = []
    for k, v in incominglinklistCount_list:
        if v > 1:
            networkednodes.append(k)
    for k, v in srtededg:
        count += 1
        ks = str(k)
        vs = str(v)
        counts = str(count)
        ksn = '"'+ks+'"'
        vsn = '"'+vs+'"'
        countn = '"'+counts+'"'
        graph.addEdge(counts, ksn, vsn)
        ge = graph.addEdge(counts, ksn, vsn)
    graphname = s+'.gexf'
    print '\n'
    print 'Created Gephi file:'+graphname
    output_file=open(graphname,"w")
    gexf.write(output_file)
    output_file.close()  





create_gexf(indicator, a, edges_new)
                 


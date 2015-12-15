import sys
import os
import re
import csv
import dateutil.parser as dparser
import hashlib
import time
import datetime
from stix.core import STIXPackage, STIXHeader
from datetime import datetime
from dateutil.tz import tzutc
from stix.common import Confidence
from stix.campaign import *
from stix.threat_actor import *
from stix.indicator import Indicator, CompositeIndicatorExpression
from stix.ttp import TTP
from stix.common.kill_chains import *
from cybox.core import Observable
from cybox.objects.file_object import File
from cybox.objects.address_object import Address
from cybox.objects.dns_record_object import *
from cybox.objects.win_registry_key_object import *
from cybox.objects.uri_object import URI
from cybox.objects.email_message_object import *
from cybox.common.hashes import Hash
from cybox.objects.memory_object import *
from stix.common.kill_chains import *
from stix.utils import set_id_namespace as stix_set_id_namespace
from cybox.utils import set_id_namespace as obs_set_id_namespace
from cybox.utils import set_id_namespace, Namespace
from cybox.core import Observable
from urllib2 import urlopen, quote
import urllib2
import json
import unicodedata
import socket
import urllib

import urllib2, base64
import feedparser

threatrecon_rss = """https://script.google.com/macros/s/AKfycbzuMTYnNfbMlN9Xvi1nXJ2YmFG_mdd5Aa9XVOnLDBrnKyARhIM/exec?676515005387440128"""
api_key = 'YOUR API KEY HERE'
query_type = 'reference'
query_url = "https://api.threatrecon.co/api/v1/search/reference"

d = feedparser.parse(threatrecon_rss)

print 'WARNING - FREE API KEYS ONLY RETURN 50 INDICATORS'

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def query_threat_recon(indicator, api_key, query_url, query_type):
    params = urllib.urlencode({'api_key': api_key, query_type: indicator})
    f = urllib2.urlopen(query_url, params)
    data = json.load(f)
    results = data["Results"]
    #print results
    return results


def convert_confidence(confidence):
    if confidence >= 75:
        return 'High'
    if confidence >= 50 and confidence < 75:
        return 'Medium'
    if confidence < 50 and confidence >= 25:
        return 'Low'
    if confidence <= 25:
        return 'None'


def generate_indicator_description(attribution,comment):
    if len(attribution) != 0:
        attribution = 'Attribution:'+attribution
    if len(comment) != 0:
        comment = 'Comment:'+comment
    description = '<![CDATA['+attribution+','+comment+']]>'
    if description.startswith(',,'):
                    description = description[2:]
                    return description
    if description.startswith(','):
                    description = description[1:]    
                    return description
    else:
                    return description
                

def generate_short_description(tags, process_type):
    if len(tags) != 0:
        short_description = 'Process_type:'+process_type+',Tags:'+tags
        return short_description
    else:
        short_description = 'Process_type:'+process_type
        return short_description
        


def add_stix_indicator_regular(indicator_db,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,stixobject,stix_package):
    comment2 = comment.decode('utf8', 'ignore')
    if len(item_reference) != 0:
        indicator.alternative_id = item_reference
    indicator.description = generate_indicator_description(attribution,comment2)
    indicator.short_description = generate_short_description(tags,process_type)
    indicator.set_producer_identity(source)
    indicator.confidence = convert_confidence(confidence)
    indicator.add_object(stixobject)
    
    #indicator.kill_chain_phases = KillChainPhaseReference()
    #indicator.kill_chain_phases.kill_chain_name = str(killchain)
    stix_package.add_indicator(indicator)
    if last_seen != 'UNK' and last_seen != '-UNK-':
        indicator.set_produced_time(last_seen)


def create_stix_package(reference,results):
    stix_package = STIXPackage()

    STIX_NAMESPACE = {"http://wapacklabs.com" : "wapack"}

    OBS_NAMESPACE = Namespace("http://wapacklabs.com", "wapack")

    stix_set_id_namespace(STIX_NAMESPACE)

    obs_set_id_namespace(OBS_NAMESPACE)
    
    stix_header = STIXHeader()

    fusionreport_title = reference
    timestring = time.time()
    formatted_timestring = datetime.fromtimestamp(timestring).strftime('%Y_%m_%d')
    stix_file_name = fusionreport_title+'_stix_package_TR_'+formatted_timestring+'.xml'


    
    stix_header.description = 'This STIX package includes indicators reported to the Red Sky community. Please send all inquiries to chall@wapacklabs.com'
    stix_package.stix_header = stix_header
    for item in results:
        process_type = str(item["ProcessType"]).decode('utf-8')
        if process_type == 'Direct':
            indicator = str(item["Indicator"]).decode('utf-8')
            #print indicator
            item_reference = str(item["Reference"]).decode('utf-8')
            source = str(item["Source"]).decode('utf-8')
            killchain = str(item["KillChain"]).decode('utf-8')
            first_seen = str(item["FirstSeen"]).decode('utf-8')
            last_seen = str(item["LastSeen"]).decode('utf-8')
            attribution = str(item["Attribution"]).decode('utf-8')
            indicator_type = str(item["Type"]).decode('utf-8')               
            rrname = str(item["Rrname"])
            rdata = str(item["Rdata"])
            rootnode = str(item["RootNode"])
            country = str(item["Country"]).decode('utf-8')
            tags = str(item["Tags"]).decode('utf-8')
            comment2 = item["Comment"]
            comment = unicodedata.normalize('NFKD', comment2).encode('ascii','ignore')
            confidence = str(item["Confidence"]).decode('utf-8')

            if indicator_type == 'MD5' or indicator_type == 'SHA1':
                f = File()
                hashval = indicator
                hashval2 = hashval.decode('utf8', 'ignore')
                f.add_hash(hashval2)
                indicator = Indicator()
                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,f,stix_package)
            if indicator_type == 'Registry':
                reg = WinRegistryKey()
                key = indicator
                key_add = key.decode('utf8', 'ignore')
                reg.key = key_add
                indicator = Indicator()
                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,reg,stix_package)
            if indicator_type == 'Subject':
                email_subj_obj = EmailMessage()
                email_subj_obj.header = EmailHeader()
                subj = indicator
                subj_add = subj.decode('utf8', 'ignore')
                email_subj_obj.header.subject = subj_add
                indcator = Indicator()
                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,email_subj_obj,stix_package) 
            if indicator_type == 'File':
                filename = File()
                file_name_fix = indicator
                file_name_fix2 = file_name_fix.decode('utf8', 'ignore')
                filename.file_name = file_name_fix2
                indicator = Indicator()
                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,filename,stix_package)
            if indicator_type == 'Email':
                email = Address()
                email.address_value = indicator.decode('utf8', 'ignore')
                email.category = Address.CAT_EMAIL
                indicator = Indicator()
                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,email,stix_package)
            if indicator_type == 'Domain':
                domain = URI()
                domainval = indicator.decode('utf8', 'ignore')
                domain.value = domainval.decode('utf8', 'ignore')
                domain.type_ = URI.TYPE_DOMAIN
                indicator = Indicator()
                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,domain,stix_package)
            if indicator_type == 'IP':
                ip = Address()
                ip.address_value = indicator.decode('utf8', 'ignore')
                ip.category = Address.CAT_IPV4
                indicator = Indicator()
                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,ip,stix_package)
            if indicator_type == 'String':
                strng = Memory()
                string = indicator
                strng.name = string.decode('utf8', 'ignore')
                indicator = Indicator()
                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,strng,stix_package)
            if indicator_type == 'URL':
                url = URI()
                url_indicator = indicator
                url.value = url_indicator.decode('utf8', 'ignore')
                url.type_ = URI.TYPE_URL
                indicator = Indicator()

                add_stix_indicator_regular(indicator,indicator,item_reference,tags,source,last_seen,confidence,process_type,comment,killchain,attribution,url,stix_package)

    f = open(stix_file_name, "w")
    a = stix_package.to_xml()

    f.write(a)

    f.close()

for post in d.entries:
    description = post.summary_detail
    try:
        value = str(description.value)
    except:
        continue
    reference = find_between( value, "&lt;reference&gt;", "&lt;/reference&gt;" )
    if len(reference) != 0:
        print 'Creating STIX package from Threat Recon for report '+ reference
        results = query_threat_recon(reference, api_key, query_url, query_type)
        if results is None:
            print 'Indicators not available yet.. try later'
        if results != None:
            create_stix_package(reference,results)




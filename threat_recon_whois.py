from whois_extractor import cRegexSearcher
import netaddr
import re
import urllib
from urllib2 import urlopen, quote
import urllib2
import json
import time
import datetime
import csv
import unicodedata
import subprocess
import StringIO

timestring = time.time()
formatted_timestring = datetime.datetime.fromtimestamp(timestring).strftime('%Y_%m_%d')


api_key = 'my API key'

search = raw_input("Please Enter an indicator: ")
def search_is_domain(strg, search=re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", re.I).search):
    return bool(search(strg))

def search_is_IP(strg, search=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", re.I).search):
    return bool(search(strg))

def search_is_cidr(strg, search=re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(\d\d))$", re.I).search):
    return bool(search(strg))

def search_is_netrange(strg, search=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]) - (([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", re.I).search):
    return bool(search(strg))

def get_cidr_from_range(netrange):
    ips = netrange.split(' - ')
    ip1 = ips[0]
    ip2 = ips[1]
    a = str(netaddr.iprange_to_cidrs(ip1, ip2))                
    cidr_proc = a.lstrip("""[IPNetwork('""")
    cidr_proc2 = cidr_proc.rstrip("""')]""")
    return cidr_proc2


def query_threat_recon(indicator, api_key):
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    f = urllib2.urlopen("https://api.threatrecon.co:8080/api/v1/search", params)
    data = json.load(f)
    results = data["Results"]
    #print json.dumps(data, indent=4, sort_keys=False)    
    return results



#path to Whois executables needs to be configured
if search_is_domain(search):
    output = subprocess.check_output('c:\whois.exe "'+search+'"', shell=True)
if search_is_IP(search):
    output = subprocess.check_output('c:\whosip.exe "'+search+'"', shell=True)
    
print output

def extract_whois_components(record, domain_or_ip):
    whois_components_to_check = []
    fromip = []
    toip = []
    buf = StringIO.StringIO(record)
    if search_is_IP(domain_or_ip):
        netrange_list = []
        netname_list = []
        cidr_list = []
        email_list = []
        network_whois_components = []
        for line in buf.readlines():
            #print line
            line_lower = line.lower().strip()
            if 'netrange' in line_lower:
                getindicator = ''.join(line_lower.split(':')[1:])
                getindicator_str = getindicator.lstrip(' \t\n\r')
                netrange_list.append(getindicator_str)
            if 'netname' in line_lower:
                getindicator = ''.join(line_lower.split(':')[1:])
                getindicator_str = getindicator.lstrip(' \t\n\r')
                netname_list.append(getindicator_str)
            if 'inetnum' in line_lower:
                getindicator = ''.join(line_lower.split(':')[1:])
                getindicator_str = getindicator.lstrip(' \t\n\r')
                netrange_list.append(getindicator_str)
            if 'cidr' in line_lower:
                getindicator = ''.join(line_lower.split(':')[1:])
                getindicator_str = getindicator.lstrip(' \t\n\r')
                cidr_list.append(getindicator_str)
            if 'from ip' in line_lower:
                getfromIP1 = ''.join(line_lower.split(':')[1:])
                getfromIP2 = getfromIP1.lstrip(' \t\n\r')
                fromip.append(getfromIP2)
            if 'to ip' in line_lower:
                gettoIP1 = ''.join(line_lower.split(':')[1:])
                gettoIP2 = gettoIP1.lstrip(' \t\n\r')
                toip.append(gettoIP2)
        netrange = fromip[0]+' - '+toip[0]
        if search_is_netrange(netrange):
            netrange_list.append(netrange)                
        if len(netrange_list) == 0:
            search = cRegexSearcher(record)
            matches = search.regexSearch()
            for k, v in matches:
                vstring = str(v)
                kstring = str(k)
                if vstring == 'netrange':
                    netrange = kstring
                    netrange_list.append(netrange)
        if len(cidr_list) == 0:
            search = cRegexSearcher(record)
            matches = search.regexSearch()
            for k, v in matches:
                vstring = str(v)
                kstring = str(k)
                if vstring == 'cidr':
                    cidr = kstring
                    cidr_list.append(cidr)
        if len(netrange_list) != 0 and len(cidr_list) == 0:
            cidr = get_cidr_from_range(netrange)
            cidr_list.append(cidr)
        search = cRegexSearcher(record)
        matches = search.regexSearch()
        for k, v in matches:
            vstring = str(v)
            kstring = str(k)
            if vstring == 'email':
                email = kstring
                email_list.append(email)
        for items in list(set(netrange_list)):
            whois_lable = 'netrange'
            network_whois_components.append([whois_lable,items])
        for items in list(set(netname_list)):
            whois_lable = 'netname'
            network_whois_components.append([whois_lable,items])
        for items in list(set(cidr_list)):
            whois_lable = 'cidr'
            network_whois_components.append([whois_lable,items])
        for items in list(set(email_list)):
            whois_lable = 'email'
            network_whois_components.append([whois_lable,items])
        if len(network_whois_components) != 0:
            print 'Extracted Network Whois Components:'
            for k, v in network_whois_components:
                print k+':'+v
                whois_components_to_check.append(v)
    if search_is_domain(domain_or_ip):
        whois_components = []
        email_list = []
        name_server_list = []
        phone_list = []
        address_list = []
        for line in buf.readlines():
            line_lower = line.lower().strip()
            if 'email:' in line_lower:
                getindicator = ''.join(line_lower.split(':')[1:])
                getindicator_str = getindicator.lstrip(' \t\n\r')
                if len(getindicator_str) > 0:
                    email_list.append(getindicator_str)
            if line_lower.startswith('nameserver:') or line_lower.startswith('name server:'):
                getindicator = ''.join(line_lower.split(':')[1:])
                getindicator_str = getindicator.strip(' \t\n\r')                                                                
                if len(getindicator_str) > 0:
                    name_server_list.append(getindicator_str)
            if 'phone:' in line_lower or 'fax:' in line_lower:
                getindicator = ''.join(line_lower.split(':')[1:])
                getindicator_str = getindicator.strip(' \t\n\r')
                whois_lable = 'phone or fax no.'
                if len(getindicator_str) > 0:
                    phone_list.append(getindicator_str)
            if 'street' in line_lower or 'address:' in line_lower:
                getindicator = ''.join(line_lower.split(':')[1:])
                getindicator_str = getindicator.strip(' \t\n\r')
                whois_lable = 'whois address component'
                if len(getindicator_str) > 0:
                    address_list.append(getindicator_str)
        if len(email_list) == 0:
            search = cRegexSearcher(record)
            matches = search.regexSearch()
            for k, v in matches:
                vstring = str(v)
                kstring = str(k)
                if vstring == 'email':
                    newemail = kstring
                    email_list.append(newemail)
        for items in list(set(email_list)):
            whois_lable = 'whois email'
            whois_components.append([whois_lable,items])
        if len(name_server_list) == 0:
            search = cRegexSearcher(record)
            matches = search.regexSearch()
            for k, v in matches:
                vstring = str(v)
                kstring = str(k)
                if vstring == 'fqdn':
                    sub = ''.join(kstring.split('.')[:1])
                    periodcount = kstring.count('.')
                    if 'ns' in sub and periodcount > 1:
                        newnameserver = kstring
                        name_server_list.append(newnameserver)  
        for items in list(set(name_server_list)):
            whois_lable = 'name server'
            whois_components.append([whois_lable,items])
        for items in list(set(phone_list)):
            whois_lable = 'phone or fax no.'
            whois_components.append([whois_lable,items])
        for items in list(set(address_list)):
            whois_lable = 'whois address component'
            whois_components.append([whois_lable,items])
        if len(whois_components) != 0:
            print 'Extracted Whois Components:'
            for k, v in whois_components:
                print k+':'+v
                whois_components_to_check.append(v)
        print '\n'
    buf.close()
    return whois_components_to_check



whois_components_to_check = extract_whois_components(output,search)
#print whois_components_to_check

csv_file_name = 'TR_search_'+search+'_'+formatted_timestring+'.csv'


with open(csv_file_name, 'wb') as csvfile:
                indicatorwriter = csv.writer(csvfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
                indicatorwriter.writerow(['INDICATOR','REFERENCE','SOURCE','KILLCHAIN','FIRST_SEEN','LAST_SEEN','ATTRIBUTION','PROCESS_TYPE','RNAME', 'RDATA','ROOT_NODE','COUNTRY','TAGS','COMMENT','CONFIDENCE'])
                for whois_item in whois_components_to_check:
                                results = query_threat_recon(whois_item, api_key)
                                if results != None:
                                    for item in results:
                                        indicator = whois_item
                                        reference = str(item["Reference"]).decode('utf-8')
                                        source = str(item["Source"]).decode('utf-8')
                                        killchain = str(item["KillChain"]).decode('utf-8')
                                        first_seen = str(item["FirstSeen"]).decode('utf-8')
                                        last_seen = str(item["LastSeen"]).decode('utf-8')
                                        attribution = str(item["Attribution"]).decode('utf-8')
                                        process_type = str(item["ProcessType"]).decode('utf-8')
                                        rrname = str(item["Rrname"])
                                        rdata = str(item["Rdata"])
                                        rootnode = str(item["RootNode"])
                                        country = str(item["Country"]).decode('utf-8')
                                        tags = str(item["Tags"]).decode('utf-8')
                                        comment = item["Comment"]
                                        comment2 = unicodedata.normalize('NFKD', comment).encode('ascii','ignore')
                                        confidence = str(item["Confidence"]).decode('utf-8')
                                        indicatorwriter.writerow([indicator,reference,source,killchain,first_seen,last_seen,attribution,process_type,rrname,rdata,rootnode,country,tags,comment2,confidence])                      
                                    lenresults = str(len(results))
                                    print lenresults +' records added to CSV for '+ whois_item







                
                
                                     

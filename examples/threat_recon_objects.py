"""
This is a POC program that provides examples for using Threat Recon objects. These are only examples for demo purposes

* replace the api_key variable with your key
"""


import query
from api import get_api_key, APIError

api_key = get_api_key() or 'my API key'
search = 'out.se7.org'

print


a = query.query_threat_recon(search, api_key)
"""
EXAMPLE 1: Get number of results'
"""
print 'EXAMPLE 1: Number of results for search'
print '\n'
print len(a)
print '\n'
"""
Example 2:
get rdata object from second result in array. 

(other possible fields are:)
    'indicator',
    'type',
    'reference',
    'source',
    'killchain',
    'firstseen',
    'lastseen',
    'attribution',
    'processtype',
    'rrname',
    'rdata',
    'country',
    'rootnode',
    'tags',
    'comment',
    'confidence',
    'id'

"""
print 'EXAMPLE 2: RDATA Record for second result'
print '\n'
print a[1].rdata
print '\n'
print '---------------------------------------------------'

"""
EXAMPLE 3
print verbose information from 6th object in array
"""
print 'EXAMPLE 3: Verbose data for 6th record'
print '\n'
b = a[5].verbose
print b
print '\n'
print '---------------------------------------------------'
"""
Example 4
search results for items that have a country value that is not 'United States'
"""
print 'EXAMPLE 4: Search results for items that have a country value that is not United States'


c = [x for x in a if x.country != "United States" and x.country != ""]
"""
print the first result from example 4
"""
print '\n'
print c[0].country
print '\n'
print '---------------------------------------------------'

"""
example 5
Find the amount of records in array that have a confidence level greater than 60
"""
print 'EXAMPLE 5: Number of results that have a confidence greater than 60'


d = [x for x in a if x.confidence > 60]
print '\n'
print len(d)
print '\n'
print '---------------------------------------------------'



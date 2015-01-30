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
#This is a POC program that provides examples for using Threat Recon objects. These are only examples for demo purposes

#* replace the api_key variable with your key



from threatrecon import query
from threatrecon.api import get_api_key, APIError

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



confidence_total = []
for result in a:
                confidence_total.append(result.confidence)

avg_confidence =  str(sum(confidence_total)/len(a))
print 'Average Confidence for indicator:+ 'avg_confidence


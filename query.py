import re
import json
import urllib
import urllib2
from sslv3 import HTTPSHandlerV3
from api import APIError

DOMAINSTR = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"


def search_is_domain(strg, search=re.compile(DOMAINSTR, re.I).search):
    """
    Returns True if the term is a domain name; else False.
    """
    return bool(search(strg))


def query_threat_recon(indicator, api_key):
    """
    Uses an indicator and the api key to query the threat recon
    database. Returns a python dict corresponding to the JSON
    output from the server (results only).

    Will throw APIError exception if the ResponseCode < 0.
    """
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    urllib2.install_opener(urllib2.build_opener(HTTPSHandlerV3()))

    f = urllib2.urlopen("https://api.threatrecon.co/api/v1/search", params)
    data = json.load(f)
    response = data.get("ResponseCode", -99)
    if response < 0:
        raise APIError(response)

    results = data.get("Results", None)
    return results

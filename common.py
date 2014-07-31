import re
import json
import urllib
import urllib2
from os.path import expanduser
from sslv3 import HTTPSHandlerV3

DOMAINSTR = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"


class APIError(Exception):
    """
    User-defined exception for API problems.
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def get_api_key(fn=".threatrecon-apikey"):
    """
    Will return the api key stored in ~/.threatrecon-apikey or False
    if any error was encountered.
    """
    try:
        apifile = "%s/%s" % (expanduser("~"), fn)
        f = open(apifile, "r")
        api_key = f.read()
        return api_key[:-1]
    except:
        return False


def search_is_domain(
    strg,
    search=re.compile(DOMAINSTR, re.I).search
):
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
    if data['ResponseCode'] < 0:
        err = "API Error"
        if data['ResponseCode'] == -1:
            err = "Invalid API Key"
        raise APIError(err)

    results = data.get("Results", None)
    return results

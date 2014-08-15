import json
import urllib
import urllib2
from sslv3 import HTTPSHandlerV3
from datetime import datetime
from dateutil import parser
from api import API_FIELDS, APIError


def raw_query_threat_recon(indicator, api_key):
    """
    Uses an indicator and the api key to query the threat recon
    database. Returns a list of python dicts corresponding to
    the JSON output from the server (results only). If no results,
    returns an empty list.

    Will throw APIError exception if the ResponseCode < 0.
    """
    params = urllib.urlencode({'api_key': api_key, 'indicator': indicator})
    urllib2.install_opener(urllib2.build_opener(HTTPSHandlerV3()))

    f = urllib2.urlopen("https://api.threatrecon.co/api/v1/search", params)
    data = json.load(f)
    response = data.get("ResponseCode", -99)
    if response < 0:
        raise APIError(response)

    results = data.get("Results", [])
    return results or []


def query_threat_recon(indicator, api_key):
    """
    Calls _raw_query_threat_recon and returns a list of TRIndicator
    objects with appropriate attributes set.
    """
    results = []
    for r in raw_query_threat_recon(indicator, api_key):
        i = TRIndicator(**r)
        i._query_root = (
            i.rootnode == '' and
            i.indicator == indicator
        )

        results.append(i)
    return results


class TRIndicator(object):
    """
    Default class for Threat Recon Indicator objects.
    """
    # replaces Result object

    def __repr__(self):
        return "TRIndicator %s [id %d type %s confidence %d%s]" % (
            self.indicator,
            self.id,
            self.type,
            self.confidence,
            " ***QUERY ROOT***" if self._query_root else ""
        )

    @property
    def verbose(self):
        r = "\n"
        for i in API_FIELDS:
            r += "%s: %s\n" % (i, getattr(self, i, None))
        if self._query_root:
            r += "***This is the query root record***\n"

        return r

    def __init__(self, *args, **kwargs):
        kwargsl = {k.lower(): v for k, v in kwargs.items()}
        for i in API_FIELDS:
            if i in kwargsl:
                v = kwargsl[i]
                if (i == 'firstseen') or (i == 'lastseen'):
                    try:
                        v = parser.parse(v)
                    except TypeError:
                        v = datetime.min
            else:
                v = None
            setattr(self, i, v)

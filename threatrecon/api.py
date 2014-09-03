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


from os.path import expanduser


API_URL = "https://api.threatrecon.co/api/v1/search"
# TODO : validate response codes with formal API docs
API_RESPONSES = {
    -99:    "General API Response Error",
    -1:     "Invalid API Key",
}

API_FIELDS = [
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
    'id',
]

API_FILENAME = ".threatrecon-apikey"

class APIError(Exception):
    """
    User-defined exception for API problems.
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%s (%d)" % (
            API_RESPONSES.get(self.value, "Unknown API Error"), self.value
        )


def get_api_key(fn=API_FILENAME):
    """
    Will return the api key stored in API_FILENAME (default
    ~/.threatrecon-apikey) or False
    if any error was encountered.
    """
    try:
        apifile = "%s/%s" % (expanduser("~"), fn)
        f = open(apifile, "r")
        api_key = f.read()
        return api_key[:-1]
    except:
        return False

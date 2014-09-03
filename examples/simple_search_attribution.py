#!/usr/bin/env python

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


import socket
import json
import argparse
import threatrecon as tr


search_default = 'Energetic Bear'
api_key_default = tr.api.get_api_key() or 'my API key'




if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Query the ThreatRecon database'
    )
    parser.add_argument(
        'search_indicator',
        default=search_default,
        nargs="?"
    )
    parser.add_argument(
        '-k', '--api-key', '--key',
        dest="api_key",
        default=api_key_default,
        help="your API key (overrides ~/%s)" % (tr.api.API_FILENAME)
    )

    args = parser.parse_args()
    api_key = args.api_key
    search = args.search_indicator
    print "***** Searching attribution %s" % search
    print "***** WARNING - FREE ACCOUNTS ARE LIMITED TO 50 RESULTS"

    try:
        results = tr.query.raw_query_threat_recon_attribution(search, api_key)
    except tr.api.APIError as e:
        print "***** API Error: %s" % e
        exit(1)

    if results:
        print "%s" % json.dumps(results, indent=4, sort_keys=False)

    else:
        # No results - check host IP
        print "***** No results found for search term %s..." % search

    exit(0)

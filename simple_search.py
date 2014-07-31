#!/usr/bin/env python
import socket
import json
import argparse
from api import get_api_key, APIError
from query import search_is_domain, query_threat_recon

search_default = 'serval.essanavy.com'
api_key_default = get_api_key() or 'my API key'


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
        help="your API key (overrides ~/.threatrecon-apikey)"
    )

    args = parser.parse_args()
    api_key = args.api_key
    search = args.search_indicator
    print "***** Searching %s" % search

    try:
        results = query_threat_recon(search, api_key)
    except APIError as e:
        print "***** API Error: %s" % e
        exit(1)

    if results:
        print "%s" % json.dumps(results, indent=4, sort_keys=False)

    else:
        # No results - check host IP
        print "***** No results found for search term %s..." % search
        if search_is_domain(search):
            print "***** %s is a valid domain." % search
            # This is a valid domain name: try reversing DNS
            try:
                iplookup = socket.gethostbyname(search)
                print "***** Checking host IP: %s\n" % iplookup
                try:
                    results = query_threat_recon(iplookup, api_key)
                except APIError as e:
                    print "***** API Error: %s" % e
                    exit(1)
                if results:
                    # DNS lookup successful and we have results
                    print "%s" % json.dumps(results, indent=4, sort_keys=False)
                else:
                    # DNS lookup successful and there were no results.
                    print "***** No results found for IP %s." % iplookup
            except socket.gaierror as e:
                # DNS lookup unsuccessful.
                print "***** Error in IP lookup: %s." % e
            except Exception as e:
                raise
        else:
            # This is not a valid domain name. Abort.
            print "***** %s is not a valid domain. Search terminated." % search
    exit(0)

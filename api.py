from os.path import expanduser

# TODO : validate response codes with formal API docs
API_RESPONSES = {
    -99:    'General API Response Error',
    -1:     'Invalid API Key',
}


class APIError(Exception):
    """
    User-defined exception for API problems.
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr("%s (%d)" % (
            API_RESPONSES.get(self.value, "Unknown API Error"), self.value)
        )


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

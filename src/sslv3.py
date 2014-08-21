import urllib2
import httplib
import ssl
import socket


# from http://bugs.python.org/issue11220
class HTTPSConnectionV3(httplib.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        httplib.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        try:
            self.sock = ssl.wrap_socket(
                sock,
                self.key_file,
                self.cert_file,
                ssl_version=ssl.PROTOCOL_SSLv3
            )
        except ssl.SSLError:
            print("Trying SSLv3.")
            self.sock = ssl.wrap_socket(
                sock,
                self.key_file,
                self.cert_file,
                ssl_version=ssl.PROTOCOL_SSLv23
            )


class HTTPSHandlerV3(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(HTTPSConnectionV3, req)

#!/usr/bin/env python

import BaseHTTPServer
import httparchive
import socket
import SocketServer
import subprocess

# TODO: How to pass args to Handler?
HTTP_ARCHIVE = None

# TODO: Need to install dig on Windows or figure out another approach.
def dns_lookup(hostname, dns_server='8.8.8.8'):
  dig = subprocess.Popen(['dig', dns_server, hostname, '+short'], stdout=subprocess.PIPE)
  short_response = dig.communicate()[0]
  short_response_lines = short_response.split('\n')
  return short_response_lines[len(short_response_lines)-2]


def get_request_body(headers, rfile):
    length = int(headers.getheader('content-length'))
    if not length:
      return None
    return rfile.read(length)


class RecordHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    request_body = get_request_body(self.headers, self.rfile)
    host = self.headers.getheader('host')
    host_ip = dns_lookup(host)

    # TODO: Connect to |host_ip|, send same request and set response.
    response = ''

    self.wfile.write(response)

    # TODO: Are any request headers besides 'host' important?
    HTTP_ARCHIVE.add(httparchive.URLArchive(host, self.path, request_body, response))

  def do_POST(self):
    self.do_GET()


class ReplayHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    request_body = get_request_body(self.headers, self.rfile)
    host = self.headers.getheader('host')
    

  def do_POST(self):
    self.do_GET()


# TODO: Probably need to start up on both 80 for http and 443 for https.
class HTTPProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  def __init__(self, record, http_archive=None, ip='localhost', port=80):
    HTTP_ARCHIVE = HTTP_ARCHIVE
    if record:
      BaseHTTPServer.HTTPServer.__init__(self, (ip, port), RecordHandler)
    else:
      BaseHTTPServer.HTTPServer.__init__(self, (ip, port), ReplayHandler)

  def get_http_archive(self):
    return HTTP_ARCHIVE

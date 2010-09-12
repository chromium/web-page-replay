#!/usr/bin/env python

import BaseHTTPServer
import socket
import SocketServer
import subprocess


# TODO: Need to install dig on Windows or figure out another approach.
def dns_lookup(hostname, dns_server='8.8.8.8'):
  dig = subprocess.Popen(['dig', dns_server, hostname, '+short'], stdout=subprocess.PIPE)
  short_response = dig.communicate()[0]
  short_response_lines = short_response.split('\n')
  return short_response_lines[len(short_response_lines)-2]


class RecordHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET():
    pass

  def do_POST():
    pass


class ReplayHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET():
    pass

  def do_POST():
    pass


# TODO: Probably need to start up on both 80 for http and 443 for https.
class HTTPProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  def __init__(self, record, ip='localhost', port=80):
    if record:
      BaseHTTPServer.HTTPServer.__init__(self, (ip, port), RecordHandler)
    else:
      BaseHTTPServer.HTTPServer.__init__(self, (ip, port), ReplayHandler)

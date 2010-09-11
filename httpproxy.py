#!/usr/bin/env python

import BaseHTTPServer
import socket
import SocketServer


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


class HTTPProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  def __init__(self, record, ip='localhost', port=80):
    if record:
      BaseHTTPServer.HTTPServer.__init__(self, (ip, port), RecordHandler)
    else:
      BaseHTTPServer.HTTPServer.__init__(self, (ip, port), ReplayHandler)

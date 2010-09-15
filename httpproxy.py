#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import BaseHTTPServer
import httparchive
import socket
import SocketServer
import subprocess


# TODO: Need to install dig on Windows or figure out another approach.
def dns_lookup(hostname, dns_server='8.8.8.8'):
  dig = subprocess.Popen(
      ['dig', dns_server, hostname, '+short'], stdout=subprocess.PIPE)
  short_response = dig.communicate()[0]
  short_response_lines = short_response.split('\n')
  return short_response_lines[-2]


def get_request_body(headers, rfile):
  length = int(headers.getheader('content-length')) or None
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
    http_request = httparchive.HTTPRequest(host, self.path, request_body)
    self.server.http_archive[http_request] = response

  def do_POST(self):
    self.do_GET()


class ReplayHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    request_body = get_request_body(self.headers, self.rfile)
    host = self.headers.getheader('host')
    http_request = httparchive.HTTPRequest(host, self.path, request_body)
    response = self.server.http_archive.get(http_request)
    if response:
      self.wfile.write(response)
    else:
      self.send_error(404)

  def do_POST(self):
    self.do_GET()


# TODO: Probably need to start up on both 80 for http and 443 for https.
class HTTPProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  def __init__(self, http_archive, host='localhost', port=80):
    self.http_archive = http_archive or httparchive.HTTPArchive()
    if self.http_archive:
      print 'Replaying on (%s:%s)...' % (host, port)
    else:
      print 'Recording on (%s:%s)...' % (host, port)
    BaseHTTPServer.HTTPServer.__init__(self, (host, port), ReplayHandler)

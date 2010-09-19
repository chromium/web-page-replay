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
import httplib
import logging
import socket
import SocketServer
import subprocess


def get_request_body(headers, rfile):
  request_body = None
  length = int(headers.getheader('content-length') or 0) or None
  if length:
    request_body = rfile.read(length)
  return request_body


def get_header_dict(headers):
  dict = {}
  for key in headers:
    dict[key] = headers[key]
  return dict


class RecordHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    request_body = get_request_body(self.headers, self.rfile)
    host = self.headers.getheader('host')
    host_ip = self.server.dns_lookup(host)
    headers = get_header_dict(self.headers)

    logging.debug('Record do_GET: %s %s', host, self.path)

    conn = httplib.HTTPConnection(host_ip)
    conn.request(self.command, self.path, request_body, headers)
    response = conn.getresponse()

    self.send_response(response.status, response.reason)
    for header, value in response.getheaders():
      self.send_header(header, value)
    self.end_headers()
    response_data = response.read()
    conn.close()

    self.wfile.write(response_data)

    # TODO: Are any request headers besides 'host' important?
    http_request = httparchive.HttpRequest(host, self.path, request_body)
    self.server.http_archive[http_request] = response_data

  def do_POST(self):
    self.do_GET()


class ReplayHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    logging.debug('Replay do_GET: %s', host)
    request_body = get_request_body(self.headers, self.rfile)
    host = self.headers.getheader('host')
    http_request = httparchive.HttpRequest(host, self.path, request_body)
    response = self.server.http_archive.get(http_request)
    if response:
      self.wfile.write(response)
    else:
      self.send_error(404)

  def do_POST(self):
    self.do_GET()


# TODO: Probably need to start up on both 80 for http and 443 for https.
class HttpProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  def __init__(self, http_archive, dns_lookup, host='localhost', port=80):
    self.http_archive = http_archive or httparchive.HttpArchive()
    self.dns_lookup = dns_lookup
    if self.http_archive:
      logging.info('Replaying on (%s:%s)...', host, port)
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), ReplayHandler)
    else:
      logging.info('Recording on (%s:%s)...', host, port)
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), RecordHandler)

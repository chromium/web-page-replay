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

import cPickle
import BaseHTTPServer
import httparchive
import httplib
import logging
import socket
import SocketServer
import subprocess

import third_party
import dns.resolver


def real_dns_lookup(hostname, dns_server='8.8.8.8'):
  resolver = dns.resolver.get_default_resolver()
  resolver.nameservers = [dns_server]
  answers = resolver.query(hostname, 'A')
  ip = None
  if answers:
    ip = str(answers[0])
  logging.debug('dns_lookup(%s), answer: %s', hostname, ip)
  return ip


def real_http_request(host_ip, request, headers):
  conn = httplib.HTTPConnection(host_ip)
  conn.request(request.command, request.path, request.request_body, headers)
  response = conn.getresponse()
  archived_http_response = httparchive.ArchivedHttpResponse(
      response.status, response.reason, response.getheaders(), response.read())
  conn.close()
  return archived_http_response

    
class HttpArchiveHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def read_request_body(self):
    request_body = None
    length = int(self.headers.getheader('content-length') or 0) or None
    if length:
      request_body = self.rfile.read(length)
    return request_body

  def get_header_dict(self):
    dict = {}
    for key in self.headers:
      dict[key] = self.headers[key]
    return dict

  def get_archived_http_request(self):
    request_body = self.read_request_body()
    headers = self.get_header_dict()
    host = self.headers.getheader('host')

    return httparchive.ArchivedHttpRequest(
        self.command, host, self.path, request_body)

  def send_archived_http_response(self, response):
    self.send_response(response.status, response.reason)
    for header, value in response.headers:
      self.send_header(header, value)
    self.end_headers()
    self.wfile.write(response.response_data)
    

class RecordHandler(HttpArchiveHandler):
  def do_GET(self):
    request = self.get_archived_http_request()
    host_ip = real_dns_lookup(request.host)
    response = real_http_request(host_ip, request, self.get_header_dict())
    self.send_archived_http_response(response)
    self.server.http_archive[request] = response
    logging.debug('Recorded: %s', request)

  def do_POST(self):
    self.do_GET()


class ReplayHandler(HttpArchiveHandler):
  def do_GET(self):
    request = self.get_archived_http_request()
    if request in self.server.http_archive:
      self.send_archived_http_response(self.server.http_archive[request])
      logging.debug('Replayed: %s', request)
    else:
      self.send_error(404)
      logging.error('Could not replay: %s', request)

  def do_POST(self):
    self.do_GET()


# TODO: Need to start up on both 80 for http and 443 for https.
class HttpProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  def __init__(self, record, http_archive_filename, host='localhost', port=80):
    self.record = record
    self.archive_filename = http_archive_filename
    self.archive_file = open(self.archive_filename, self.record and 'w' or 'r')
    if self.record:
      self.http_archive = httparchive.HttpArchive()
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), RecordHandler)
      logging.info('Recording on (%s:%s)...', host, port)
    else:
      self.http_archive = cPickle.load(self.archive_file)
      self.archive_file.close()
      logging.info('Loaded %d responses from %s',
                   len(self.http_archive), self.archive_filename)
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), ReplayHandler)
      logging.info('Replaying on (%s:%s)...', host, port)

  def cleanup(self):
    self.shutdown()
    logging.info('Stopped HTTP server')
    if self.record and self.archive_file:
      cPickle.dump(self.http_archive, self.archive_file)
      self.archive_file.close()
      logging.info('Saved %d response to %s',
                   len(self.http_archive), self.archive_filename)


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
import daemonserver
import httparchive
import httplib
import logging
import os
import socket
import SocketServer
import subprocess
import time


class RealHttpRequest(object):
  def __init__(self, real_dns_lookup):
    self._real_dns_lookup = real_dns_lookup

  def __call__(self, request, headers):
    logging.debug('RealHttpRequest: %s %s', request.host, request.path)
    host_ip = self._real_dns_lookup(request.host)
    try:
      connection = httplib.HTTPConnection(host_ip)
      connection.request(
          request.command,
          request.path,
          request.request_body,
          headers)
      response = connection.getresponse()

      # On the response, we'll save every read exactly as we read it
      # from the network.  We'll use this to replay chunks similarly to
      # how we recorded them.
      response.raw_data = []
      return response
    except Exception, e:
      logging.critical('Could not fetch %s: %s', request, e)
      return None


class HttpArchiveHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  protocol_version = "HTTP/1.1"

  # Make it match our logging format
  def log_request(self, code='-', size='-'): pass
  def log_error(self, format, *args): logging.error(format, *args)
  def log_message(self, format, *args): logging.info(format, *args)

  def read_request_body(self):
    request_body = None
    length = int(self.headers.get('content-length', 0)) or None
    if length:
      request_body = self.rfile.read(length)
    return request_body

  def get_header_dict(self):
    return dict(self.headers.items())

  def get_archived_http_request(self):
    host = self.headers.get('host')
    if host == None:
      logging.error("Request without host header")
      return None

    return httparchive.ArchivedHttpRequest(
        self.command,
        host,
        self.path,
        self.read_request_body())

  def send_archived_http_response(self, response):
    try:
      # We need to set the server name before we start the response.
      # Take a scan through the response headers here
      use_chunked = False
      has_content_length = False
      server_name = "WebPageReplay"
      for header, value in response.headers:
        if header == "server":
          server_name = value
        if header == "transfer-encoding":
          use_chunked = True
        if header == "content-length":
          has_content_length = True
      self.server_version = server_name
      self.sys_version = ""

      if response.version == 10:
        self.protocol_version = "HTTP/1.0"

      # If we don't have chunked encoding and there is no content length,
      # we need to manually compute the content-length.
      if not use_chunked and not has_content_length:
        content_length = 0
        for item in response.response_data:
          content_length += len(item)
        response.headers.append(("content-length", str(content_length)))

      self.send_response(response.status, response.reason)
      # TODO(mbelshe): This is lame - each write is a packet!
      for header, value in response.headers:
        skip_header = False
        if header == "server":
          skip_header = True
        if skip_header == False:
          self.send_header(header, value)
      self.end_headers()

      for item in response.response_data:
        if use_chunked:
          self.wfile.write(str(hex(len(item)))[2:])
          self.wfile.write("\r\n")
        self.wfile.write(item)
        if use_chunked:
          self.wfile.write("\r\n")
      self.wfile.flush()

      # TODO(mbelshe): This connection close doesn't seem to work.
      if response.version == 10:
        self.close_connection = 1

    except Exception, e:
      logging.error("Error sending response for %s/%s: %s",
                       self.headers['host'],
                       self.path,
                       e)

  def do_POST(self):
    self.do_GET()

  def do_HEAD(self):
    self.do_GET()


class RecordHandler(HttpArchiveHandler):
  def do_GET(self):
    request = self.get_archived_http_request()
    if request is None:
      self.send_error(500)
      return

    response = self.server.real_http_request(request, self.get_header_dict())
    if response is None:
      self.send_error(404)
      return

    # Read the rest of the HTTP response.
    while True:
      data = response.read(4096)
      response.raw_data.append(data)
      if len(data) == 0:
        break

    archived_http_response = httparchive.ArchivedHttpResponse(
        response.version,
        response.status,
        response.reason,
        response.getheaders(),
        response.raw_data)
    if self.server.use_deterministic_script:
      archived_http_response.inject_deterministic_script()
    self.send_archived_http_response(archived_http_response)
    self.server.http_archive[request] = archived_http_response
    logging.debug('Recorded: %s', request)


class ReplayHandler(HttpArchiveHandler):
  def do_GET(self):
    start_time = time.time()
    request = self.get_archived_http_request()
    if request in self.server.http_archive:
      self.send_archived_http_response(self.server.http_archive[request])
      request_time_ms = (time.time() - start_time) * 1000.0;
      logging.debug('Replayed: %s (%dms)', request, request_time_ms)
    else:
      self.send_error(404)
      logging.error('Could not replay: %s', request)


class RecordHttpProxyServer(SocketServer.ThreadingMixIn,
                            BaseHTTPServer.HTTPServer,
                            daemonserver.DaemonServer):
  def __init__(
      self, http_archive_filename, use_deterministic_script, real_dns_lookup,
      host='localhost', port=80):
    self.use_deterministic_script = use_deterministic_script
    self.archive_filename = http_archive_filename
    self.real_http_request = RealHttpRequest(real_dns_lookup)

    self._assert_archive_file_writable()
    self.http_archive = httparchive.HttpArchive()

    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), RecordHandler)
    except Exception, e:
      logging.critical('Could not start HTTPServer on port %d: %s', port, e)
      return
    logging.info('Recording on %s:%s...', host, port)

  def _assert_archive_file_writable(self):
    archive_dir = os.path.dirname(os.path.abspath(self.archive_filename))
    assert os.path.exists(archive_dir), "Archive directory must exist."
    assert (os.access(self.archive_filename, os.W_OK) or
            (os.access(archive_dir, os.W_OK) and
             not os.path.exists(self.archive_filename))), \
             "Need permissions to write archive file"

  def cleanup(self):
    try:
      self.shutdown()
    except KeyboardInterrupt, e:
      pass
    logging.info('Stopped Record HTTP server')
    self.http_archive.Persist(self.archive_filename)
    logging.info('Saved %d responses to %s',
                 len(self.http_archive), self.archive_filename)


class ReplayHttpProxyServer(SocketServer.ThreadingMixIn,
                            BaseHTTPServer.HTTPServer,
                            daemonserver.DaemonServer):
  def __init__(
      self, http_archive_filename, use_deterministic_script, real_dns_lookup,
      host='localhost', port=80):
    self.use_deterministic_script = use_deterministic_script
    self.http_archive = httparchive.HttpArchive.Create(http_archive_filename)
    logging.info('Loaded %d responses from %s',
                 len(self.http_archive), http_archive_filename)

    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), ReplayHandler)
    except Exception, e:
      logging.critical('Could not start HTTPServer on port %d: %s', port, e)
      return
    logging.info('Replaying on %s:%s...', host, port)

  def cleanup(self):
    try:
      self.shutdown()
    except KeyboardInterrupt, e:
      pass
    logging.info('Stopped HTTP server')

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
import logging
import os
import SocketServer
import ssl
import subprocess
import time
import urlparse


class HttpArchiveHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  protocol_version = 'HTTP/1.1'  # override BaseHTTPServer setting

  # Since we do lots of small wfile.write() calls, turn on buffering.
  wbufsize = -1  # override StreamRequestHandler (a base class) setting

  # Make request handler logging match our logging format.
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

  def get_archived_http_request(self, is_ssl=False):
    host = self.headers.get('host')
    if host is None:
      logging.error('Request without host header')
      return None

    parsed = urlparse.urlparse(self.path)
    query = '?%s' % parsed.query if parsed.query else ''
    fragment = '#%s' % parsed.fragment if parsed.fragment else ''
    full_path = '%s%s%s' % (parsed.path, query, fragment)

    return httparchive.ArchivedHttpRequest(
        self.command,
        host,
        full_path,
        self.read_request_body(),
        self.get_header_dict(),
        is_ssl)

  def send_archived_http_response(self, response):
    try:
      # We need to set the server name before we start the response.
      headers = dict(response.headers)
      use_chunked = 'transfer-encoding' in headers
      has_content_length = 'content-length' in headers
      self.server_version = headers.get('server', 'WebPageReplay')
      self.sys_version = ''

      if response.version == 10:
        self.protocol_version = 'HTTP/1.0'

      # If we don't have chunked encoding and there is no content length,
      # we need to manually compute the content-length.
      if not use_chunked and not has_content_length:
        content_length = sum(len(c) for c in response.response_data)
        response.headers.append(('content-length', str(content_length)))

      self.send_response(response.status, response.reason)
      # TODO(mbelshe): This is lame - each write is a packet!
      for header, value in response.headers:
        if header != 'server':
          self.send_header(header, value)

      # For backwards compatibility
      server_delays = []
      if hasattr(response, 'server_delays'):
        server_delays = response.server_delays

      logging.debug('server delays: %s', server_delays)

      # We don't want our proxy to simulate server delay on record mode
      use_server_delay = (self.server.http_archive_fetch.use_server_delay and
                          not self.server.http_archive_fetch.is_record_mode)

      if use_server_delay and server_delays:
        time.sleep(server_delays[0] / 1000.0)
      self.end_headers()

      # Extract server delays for non-first and non-last chunks
      for chunk, delay in map(None, response.response_data,
                              server_delays[1:-1]):
        if use_chunked:
          if use_server_delay and delay:
            time.sleep(delay / 1000.0)
          # Write chunk length (hex) and data (e.g. "A\r\nTESSELATED\r\n").
          self.wfile.write('%x\r\n%s\r\n' % (len(chunk), chunk))
        else:
          self.wfile.write(chunk)
      if use_chunked and (not response.response_data or
                          response.response_data[-1]):
        if use_server_delay and server_delays:
          time.sleep(server_delays[-1] / 1000.0)
        # Write last chunk as a zero-length chunk with no data.
        self.wfile.write('0\r\n\r\n')
      self.wfile.flush()

      # TODO(mbelshe): This connection close doesn't seem to work.
      if response.version == 10:
        self.close_connection = 1

    except Exception, e:
      logging.error('Error sending response for %s/%s: %s',
                    self.headers['host'],
                    self.path,
                    e)

  def do_POST(self):
    self.do_GET()

  def do_HEAD(self):
    self.do_GET()

  def send_error(self, response_code, message=None):
    """Override the default send error with a version that doesn't unnecessarily
    close the connection.
    """
    body = "Not Found"
    self.send_response(response_code, message)
    self.send_header('content-type', 'text/plain')
    self.send_header('content-length', str(len(body)))
    self.end_headers()
    self.wfile.write(body)
    self.wfile.flush()

  def do_GET(self):
    start_time = time.time()
    request = self.get_archived_http_request()
    if request is None:
      self.send_error(500)
      return
    response_code = self.server.custom_handlers.handle(request)
    if response_code:
      self.send_error(response_code)
      return
    response = self.server.http_archive_fetch(request)
    if response:
      self.send_archived_http_response(response)
      request_time_ms = (time.time() - start_time) * 1000.0;
      logging.debug('Served: %s (%dms)', request, request_time_ms)
    else:
      self.send_error(404)


class HttpProxyServer(SocketServer.ThreadingMixIn,
                      BaseHTTPServer.HTTPServer,
                      daemonserver.DaemonServer):
  HANDLER = HttpArchiveHandler

  def __init__(self, http_archive_fetch, custom_handlers,
               host='localhost', port=80):
    self.http_archive_fetch = http_archive_fetch
    self.custom_handlers = custom_handlers

    # Increase the listen queue size. The default, 5, is set in
    # SocketServer.TCPServer (the parent of BaseHTTPServer.HTTPServer).
    # Since we're intercepting many domains through this single server,
    # it is quite possible to get more than 5 concurrent connection requests.
    self.request_queue_size = 128

    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), self.HANDLER)
    except Exception, e:
      logging.critical('Could not start HTTPServer on port %d: %s', port, e)
    logging.info('Started HTTP server on %s...', self.server_address)

  def cleanup(self):
    try:
      self.shutdown()
    except KeyboardInterrupt, e:
      pass
    logging.info('Stopped HTTP server')


class HttpsArchiveHandler(HttpArchiveHandler):
  """SSL handler."""

  def get_archived_http_request(self):
    logging.debug('Get request via SSL.')
    request = HttpArchiveHandler.get_archived_http_request(self, is_ssl=True)
    request.is_ssl = True
    return request

class HttpsProxyServer(HttpProxyServer):
  """SSL server."""

  HANDLER = HttpsArchiveHandler

  def __init__(self, http_archive_fetch, custom_handlers, certfile,
               host='localhost', port=443):
    HttpProxyServer.__init__(
        self, http_archive_fetch, custom_handlers, host, port)
    self.socket = ssl.wrap_socket(self.socket, certfile=certfile,
                                  server_side=True)
    # Ancestor class, deamonserver, calls serve_forever() during its __init__.

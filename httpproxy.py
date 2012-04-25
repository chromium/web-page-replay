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


class HttpProxyError(Exception):
  """Module catch-all error."""
  pass

class HttpProxyServerError(HttpProxyError):
  """Raised for errors like 'Address already in use'."""
  pass


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

  def get_archived_http_request(self):
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
        self.server.is_ssl)

  def send_archived_http_response(self, response):
    try:
      # We need to set the server name before we start the response.
      is_chunked = response.is_chunked()
      has_content_length = response.get_header('content-length') is not None
      self.server_version = response.get_header('server', 'WebPageReplay')
      self.sys_version = ''

      if response.version == 10:
        self.protocol_version = 'HTTP/1.0'

      # If we don't have chunked encoding and there is no content length,
      # we need to manually compute the content-length.
      if not is_chunked and not has_content_length:
        content_length = sum(len(c) for c in response.response_data)
        response.headers.append(('content-length', str(content_length)))

      use_delays = (self.server.use_delays and
                    not self.server.http_archive_fetch.is_record_mode)
      if use_delays:
        logging.debug('Using delays: %s', response.delays)
        time.sleep(response.delays['headers'] / 1000.0)
      self.send_response(response.status, response.reason)
      # TODO(mbelshe): This is lame - each write is a packet!
      for header, value in response.headers:
        if header != 'server':
          self.send_header(header, value)
      self.end_headers()

      for chunk, delay in zip(response.response_data, response.delays['data']):
        if use_delays:
          time.sleep(delay / 1000.0)
        if is_chunked:
          # Write chunk length (hex) and data (e.g. "A\r\nTESSELATED\r\n").
          self.wfile.write('%x\r\n%s\r\n' % (len(chunk), chunk))
        else:
          self.wfile.write(chunk)
      if is_chunked:
        self.wfile.write('0\r\n\r\n')  # write final, zero-length chunk.
      self.wfile.flush()

      # TODO(mbelshe): This connection close doesn't seem to work.
      if response.version == 10:
        self.close_connection = 1

    except Exception, e:
      logging.error('Error sending response for %s/%s: %s',
                    self.headers['host'], self.path, e)

  def do_POST(self):
    self.do_GET()

  def do_HEAD(self):
    self.do_GET()

  def send_error(self, status):
    """Override the default send error with a version that doesn't unnecessarily
    close the connection.
    """
    response = httparchive.create_response(status)
    self.send_archived_http_response(response)

  def do_GET(self):
    start_time = time.time()
    request = self.get_archived_http_request()
    if request is None:
      self.send_error(500)
      return
    response = self.server.custom_handlers.handle(request)
    if not response:
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

  # Increase the request queue size. The default value, 5, is set in
  # SocketServer.TCPServer (the parent of BaseHTTPServer.HTTPServer).
  # Since we're intercepting many domains through this single server,
  # it is quite possible to get more than 5 concurrent requests.
  request_queue_size = 128

  def __init__(self, http_archive_fetch, custom_handlers,
               host='localhost', port=80, use_delays=False,
               is_ssl=False):
    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), self.HANDLER)
    except Exception, e:
      raise HttpProxyServerError('Could not start HTTPServer on port %d: %s' %
                                 (port, e))
    self.http_archive_fetch = http_archive_fetch
    self.custom_handlers = custom_handlers
    self.use_delays = use_delays
    self.is_ssl = is_ssl

    protocol = 'HTTPS' if self.is_ssl else 'HTTP'
    logging.info('Started %s server on %s...', protocol, self.server_address)

  def cleanup(self):
    try:
      self.shutdown()
    except KeyboardInterrupt, e:
      pass
    logging.info('Stopped HTTP server')


class HttpsProxyServer(HttpProxyServer):
  """SSL server."""

  def __init__(self, http_archive_fetch, custom_handlers, certfile,
               host='localhost', port=443, use_delays=False):
    HttpProxyServer.__init__(
        self, http_archive_fetch, custom_handlers, host, port,
        use_delays, is_ssl=True)
    self.socket = ssl.wrap_socket(
        self.socket, certfile=certfile, server_side=True)
    # Ancestor class, deamonserver, calls serve_forever() during its __init__.

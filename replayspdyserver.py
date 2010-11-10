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

import daemonserver
import logging
import httparchive
import os
import sys
import threading
import third_party.nbhttp.spdy_server as spdy_server
import third_party.nbhttp.push_tcp as push_tcp
from third_party.nbhttp.http_common import get_hdr, dummy
import time

CONTENT_LENGTH = 'content-length'
STATUS = 'status'
VERSION = 'version'

class ReplaySpdyServer(daemonserver.DaemonServer):
  def __init__(
      self, http_archive_filename, use_deterministic_script, real_dns_lookup,
      host='localhost', port=80):
    #TODO(lzheng): figure out how to get the log level from main.
    self.log = logging.getLogger('ReplaySpdyServer')
    self.log.setLevel(logging.INFO)
    self.http_archive = httparchive.HttpArchive.Create(http_archive_filename)
    self.log.info('Loaded %d responses from %s',
                  len(self.http_archive), http_archive_filename)
    self.host = host
    self.port = port
    self.spdy_server = spdy_server.SpdyServer(host, port,
                                              self.request_handler,
                                              self.log)

  def serve_forever(self):
    self.log.info('Replaying with SPDY on %s:%d', self.host, self.port)
    push_tcp.run()

  def cleanup(self):
    push_tcp.stop()
    self.log.info('Stopped spdy server')

  def request_handler(self, method, uri, hdrs, res_start, req_pause):
    """
    Based on method, host and uri to fetch the matching response and reply
    to browser using spdy.
    """
    host = ''
    for (name, value) in hdrs:
      if name.lower() == 'host':
        host = value
    self.log.debug("request: %s, uri: %s, method: %s", host, uri, method)

    if method == 'GET':
      request = httparchive.ArchivedHttpRequest(method, host, uri, None)
      if request in self.http_archive:
        response = self.http_archive[request]
        res_hdrs = [('version', 'HTTP/1.1')]
        for (name, value) in response.headers:
          name_lower = name.lower()
          if name.lower() == CONTENT_LENGTH:
            res_hdrs.append((name, str(value)))
          elif name_lower == STATUS:
            pass
          elif name_lower == VERSION:
            pass
          else:
            res_hdrs.append((name, value))
        res_body, res_done = res_start(str(response.status),
                                       response.reason,
                                       res_hdrs, dummy)
        body = ''
        for item in response.response_data:
          body += item
        res_body(body)
        res_done(None)
      else:
        self.log.error("404 returned: %s %s", method, uri)
        code = "404"
        phrase = "file not found"
        res_hdrs = [('Content-Type', 'text/html'), ('version', 'HTTP/1.1')]
        res_body, res_done = res_start(code, phrase, res_hdrs, dummy)
        res_body(None)
        res_done(None)
    else:
      # TODO(lzheng): Add support for other methods.
      self.log.error("method: %s is not supported: %s", method, uri)
      code = "500"
      phrase = "Not supported"
      res_hdrs = [('Content-Type', 'text/html'), ('version', 'HTTP/1.1')]
      res_body, res_done = res_start(code, phrase, res_hdrs, dummy)
      res_body(None)
      res_done(None)

    return dummy, dummy

if __name__ == "__main__":
    logging.basicConfig()
    log = logging.getLogger('server')
    log.setLevel(logging.INFO)
    filename = sys.argv[1]
    host = '127.0.0.1'
    port = 8088
    server = ReplaySpdyServer(filename, host, port)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.setDaemon(True)
    server_thread.start()
    time.sleep(60)
    server.cleanup();

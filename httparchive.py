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
import gzip
import logging
import persistentmixin
import StringIO
import sys


class HttpArchive(dict, persistentmixin.PersistentMixin):
  """Dict with ArchivedHttpRequest keys and ArchivedHttpResponse values."""

  def debug_str(self):
    """Return an archive as a string excluding binary data."""

    out = StringIO.StringIO()
    for request in self.keys():
      print >>out, request.command, request.host, request.path
      if request.request_body:
        print >>out, request.request_body
      print >>out, '-' * 70
      response = self[request]
      print >>out, 'Status: %s\nReason: %s\nheaders:\n' % (
          response.status, response.reason)
      for k, v in sorted(response.headers):
        print >>out, "    %s: %s" % (k, v)
      headers = dict(response.headers)
      content_type = headers.get('content-type', '')
      if (content_type.startswith('text/') or
          content_type == 'application/x-javascript'):
        print >>out, '-' * 70
        if headers.get('content-encoding', '') == 'gzip':
          compressed_response_data = StringIO.StringIO(response.response_data)
          print >>out, gzip.GzipFile(fileobj=compressed_response_data).read()
        else:
          print >>out, response.response_data
      print >>out, '=' * 70
    return out.getvalue()


class ArchivedHttpRequest(object):
  def __init__(self, command, host, path, request_body):
    self.command = command
    self.host = host
    self.path = path
    self.request_body = request_body

  def __repr__(self):
    return repr((self.command, self.host, self.path, self.request_body))

  def __hash__(self):
    return hash(self.__repr__())

  def __eq__(self, other):
    return self.__repr__() == other.__repr__()


class ArchivedHttpResponse(object):
  def __init__(self, status, reason, headers, response_data):
    self.status = status
    self.reason = reason
    self.headers = headers
    self.response_data = response_data

  def get_header(self, key):
    for k, v in self.headers:
      if key == k:
        return v
    return None

  def set_header(self, key, value):
    for i, (k, v) in enumerate(self.headers):
      if key == k:
        self.headers[i] = (key, value)
        return
    self.headers.append((key, value))

  def remove_header(self, key):
    for i, (k, v) in enumerate(self.headers):
      if key == k:
        self.headers.pop(i)
        return

  def inject_deterministic_script(self):
    content_type = self.get_header('content-type')
    if not content_type or not content_type.startswith('text/html'):
      return

    if not self.get_header('content-length'):
      if self.get_header('transfer-encoding') != 'chunked':
        logging.error('Failed to inject deterministic script.')
        return

      # TODO: httplib has unchunked the response_data for us, so we have to
      # strip the "transfer-encoding: chunked" header and the add content-length
      # at the end. Ideally, we'd want to preserve the chunked response instead
      # of unchunking it.
      logging.warning('Unchunked a chunked response.')
      self.remove_header('transfer-encoding')

    is_gzipped = self.get_header('content-encoding') == 'gzip'
    if is_gzipped:
      compressed_response_data = StringIO.StringIO(self.response_data)
      response_data = gzip.GzipFile(fileobj=compressed_response_data).read()
    else:
      response_data = self.response_data

    deterministic_script = """
    <script>
      (function () {
        var orig_date = Date;
        var x = 0;
        var time_seed = 1204251968254;
        Math.random = function() {
          x += .1;
          return (x % 1);
        };
        Date = function() {
          if (this instanceof Date) {
            switch (arguments.length) {
              case 0: return new orig_date(time_seed += 50);
              case 1: return new orig_date(arguments[0]);
              default: return new orig_date(arguments[0], arguments[1],
                  arguments.length >= 3 ? arguments[2] : 1,
                  arguments.length >= 4 ? arguments[3] : 0,
                  arguments.length >= 5 ? arguments[4] : 0,
                  arguments.length >= 6 ? arguments[5] : 0,
                  arguments.length >= 7 ? arguments[6] : 0);
            }
          }
          return new Date().toString();
        };
        Date.__proto__ = orig_date;
        Date.prototype.constructor = Date;
        orig_date.now = function() {
          return new Date().getTime();
        };
      })();
    </script>
    """
    len_response_data = len(response_data)
    response_data = response_data.replace(
        '<head>', '<head>%s' % deterministic_script, 1)
    if len_response_data == len(response_data):
      logging.error('Failed to inject deterministic script')

    if is_gzipped:
      compressed_response = StringIO.StringIO()
      gzip.GzipFile(fileobj=compressed_response, mode='w').write(response_data)
      self.response_data = compressed_response.getvalue()
    else:
      self.response_data = response_data
    self.set_header('content-length', len(self.response_data))


if __name__ == '__main__':
  wpr_file = sys.argv[1]
  http_archive = HttpArchive.Create(wpr_file)
  print http_archive.debug_str()

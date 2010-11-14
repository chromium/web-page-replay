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
import re
import zlib


HTML_RE = re.compile(r'<html[^>]*>', re.IGNORECASE)
HEAD_RE = re.compile(r'<head[^>]*>', re.IGNORECASE)
DETERMINISTIC_SCRIPT = """
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


def _InsertScriptAfter(matchobj):
  return matchobj.group(0) + DETERMINISTIC_SCRIPT


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
        # Concatenate the chunks so we can decompress it.
        raw_data = ""
        for item in response.response_data:
          raw_data += item
        if headers.get('content-encoding', '') == 'gzip':
          compressed_response_data = StringIO.StringIO(raw_data)
          print >>out, gzip.GzipFile(fileobj=compressed_response_data).read()
        elif headers.get('content-encoding', '') == 'deflate':
          print >>out, zlib.decompress(raw_data, -zlib.MAX_WBITS)
        else:
          print >>out, raw_data
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
  def __init__(self, version, status, reason, headers, response_data):
    self.version = version
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

    # Concatenate the chunks so we can decompress it.
    raw_data = ''.join(self.response_data)

    is_gzip = self.get_header('content-encoding') == 'gzip'
    is_deflate = self.get_header('content-encoding') == 'deflate'
    if is_gzip:
      compressed_data = StringIO.StringIO(raw_data)
      raw_data = gzip.GzipFile(fileobj=compressed_data).read()
    elif is_deflate:
      raw_data = zlib.decompress(raw_data, -zlib.MAX_WBITS)

    # First try to insert immediately after <head> then try <html>.
    if raw_data:
      raw_data, injected = HEAD_RE.subn(_InsertScriptAfter, raw_data, 1)
      if not injected:
        raw_data, injected = HTML_RE.subn(_InsertScriptAfter, raw_data, 1)
        if not injected:
          logging.debug(raw_data)
          raise

    if is_gzip:
      compressed_response = StringIO.StringIO()
      gzip.GzipFile(fileobj=compressed_response, mode='w').write(raw_data)
      raw_data = compressed_response.getvalue()
    elif is_deflate:
      raw_data = zlib.compress(raw_data)#[2:-4]  # Discard zlib header+checksum.

    self.response_data = []
    self.response_data.append(raw_data)
    self.response_data.append('')  # Append a null chunk

    if not self.get_header('transfer-encoding'):
      len_raw_data = len(self.response_data[0])
      self.set_header('content-length', len_raw_data)


if __name__ == '__main__':
  wpr_file = sys.argv[1]
  http_archive = HttpArchive.Create(wpr_file)
  print http_archive.debug_str()

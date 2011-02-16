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

"""View and edit HTTP Archives.

To list all URLs in an archive:
  $ ./httparchive.py ls archive.wpr

To view the content of all URLs from example.com:
  $ ./httparchive.py cat --host example.com archive.wpr

To view the content of a particular URL:
  $ ./httparchive.py cat --host www.example.com --path /foo archive.wpr

To view the content of all URLs:
  $ ./httparchive.py cat archive.wpr

To edit a particular URL:
  $ ./httparchive.py edit --host www.example.com --path /foo archive.wpr
"""

import httpzlib
import logging
import optparse
import os
import persistentmixin
import re
import StringIO
import subprocess
import tempfile


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


class HttpArchiveException(Exception):
  pass

class InjectionFailedException(HttpArchiveException):
  def __init__(self, text):
    self.text = text

  def __str__(self):
    return repr(text)

def _InsertScriptAfter(matchobj):
  return matchobj.group(0) + DETERMINISTIC_SCRIPT


class HttpArchive(dict, persistentmixin.PersistentMixin):
  """Dict with ArchivedHttpRequest keys and ArchivedHttpResponse values."""

  def get_requests(self, command=None, host=None, path=None):
    """Retruns a list of all requests matching giving params."""
    return [r for r in self if r.matches(command, host, path)]

  def ls(self, command=None, host=None, path=None):
    """List all URLs that match given params."""
    out = StringIO.StringIO()
    for request in self.get_requests(command, host, path):
      print >>out, '%s %s%s' % (request.command, request.host, request.path)
    return out.getvalue()

  def cat(self, command=None, host=None, path=None):
    """Print the contents of all URLs that match given params."""
    out = StringIO.StringIO()
    for request in self.get_requests(command, host, path):
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
      body = response.get_data_as_text()
      if body:
        print >>out, '-' * 70
        print >>out, body
      print >>out, '=' * 70
    return out.getvalue()

  def edit(self, command=None, host=None, path=None):
    """Edits the single request which matches given params."""
    editor = os.getenv('EDITOR')
    if not editor:
      print 'You must set the EDITOR environmental variable.'
      return

    matching_requests = self.get_requests(command, host, path)
    if not matching_requests:
      print 'Failed to find any requests matching given command, host, path.'
      return

    if len(matching_requests) > 1:
      print 'Found multiple matching requests. Please refine.'
      print self.ls(command, host, path)

    response = self[matching_requests[0]]
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    tmp_file.write(response.get_data_as_text())
    tmp_file.close()
    subprocess.check_call([editor, tmp_file.name])
    response.set_body_text(''.join(open(tmp_file.name).readlines()))
    os.remove(tmp_file.name)


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

  def matches(self, command=None, host=None, path=None):
    """Returns true iff the request matches all parameters."""
    return ((command is None or command == self.command) and
            (host is None or host == self.host) and
            (path is None or path == self.path))


class ArchivedHttpResponse(object):
  """HTTPResponse objects.

  ArchivedHttpReponse instances have the following attributes:
    version: HTTP protocol version used by server.
        10 for HTTP/1.0, 11 for HTTP/1.1 (same as httplib).
    status: Status code returned by server (e.g. 200).
    reason: Reason phrase returned by server (e.g. "OK").
    headers: list of (header, value) tuples.
    response_data: list of content chunks. Concatenating all the content chunks
        gives the complete contents (i.e. the chunks do not have any lengths or
        delimiters).
  """

  # CHUNK_EDIT_SEPARATOR is used to edit and view text content.
  # It is not sent in responses. It is added by get_data_as_text()
  # and removed by set_data().
  CHUNK_EDIT_SEPARATOR = '[WEB_PAGE_REPLAY_CHUNK_BOUNDARY]'

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

  def is_gzip(self):
    return self.get_header('content-encoding') == 'gzip'

  def is_compressed(self):
    return self.get_header('content-encoding') in ('gzip', 'deflate')

  def get_data_as_text(self):
    """Return content as a single string.

    Uncompresses and concatenates chunks with CHUNK_EDIT_SEPARATOR.
    """
    content_type = self.get_header('content-type')
    if (not content_type or
        not (content_type.startswith('text/') or
             content_type == 'application/x-javascript')):
      return None
    if self.is_compressed():
      uncompressed_chunks = httpzlib.uncompress_chunks(
          self.response_data, self.is_gzip())
    else:
      uncompressed_chunks = self.response_data
    return self.CHUNK_EDIT_SEPARATOR.join(uncompressed_chunks)

  def set_data(self, text):
    """Inverse of set_data_as_text().

    Split on CHUNK_EDIT_SEPARATOR and compress if needed.
    """
    text_chunks = text.split(self.CHUNK_EDIT_SEPARATOR)
    if self.is_compressed():
      self.response_data = httpzlib.compress_chunks(text_chunks, self.is_gzip())
    else:
      self.response_data = text_chunks
    if not self.get_header('transfer-encoding'):
      content_length = sum(len(c) for c in response.response_data)
      self.set_header('content-length', str(content_length))

  def inject_deterministic_script(self):
    """Inject deterministic script immediately after <head> or <html>."""
    content_type = self.get_header('content-type')
    if not content_type or not content_type.startswith('text/html'):
      return
    text = self.get_data_as_text()
    if text:
      text, is_injected = HEAD_RE.subn(_InsertScriptAfter, text, 1)
      if not is_injected:
        text, is_injected = HTML_RE.subn(_InsertScriptAfter, text, 1)
        if not is_injected:
          raise InjectionFailedException(text)
      self.set_data(text)


if __name__ == '__main__':
  class PlainHelpFormatter(optparse.IndentedHelpFormatter):
    def format_description(self, description):
      if description:
        return description + '\n'
      else:
        return ''

  option_parser = optparse.OptionParser(
      usage='%prog [ls|cat|edit] [options] replay_file',
      formatter=PlainHelpFormatter(),
      description=__doc__,
      epilog='http://code.google.com/p/web-page-replay/')

  option_parser.add_option('-c', '--command', default=None,
      action='store',
      type='string',
      help='Only show URLs matching this command.')
  option_parser.add_option('-o', '--host', default=None,
      action='store',
      type='string',
      help='Only show URLs matching this host.')
  option_parser.add_option('-p', '--path', default=None,
      action='store',
      type='string',
      help='Only show URLs matching this path.')

  options, args = option_parser.parse_args()

  if len(args) != 2:
    print 'args: %s' % args
    option_parser.error('Must specify a command and replay_file')

  command = args[0]
  replay_file = args[1]

  if not os.path.exists(replay_file):
    option_parser.error('Replay file "%s" does not exist' % replay_file)

  http_archive = HttpArchive.Create(replay_file)
  if command == 'ls':
    print http_archive.ls(options.command, options.host, options.path)
  elif command == 'cat':
    print http_archive.cat(options.command, options.host, options.path)
  elif command == 'edit':
    http_archive.edit(options.command, options.host, options.path)
    http_archive.Persist(replay_file)
  else:
    option_parser.error('Unknown command "%s"' % command)

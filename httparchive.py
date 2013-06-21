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

To print statistics of an archive:
  $ ./httparchive.py stats archive.wpr

To print statistics of a set of URLs:
  $ ./httparchive.py stats --host www.example.com archive.wpr

To merge multiple archives
  $ ./httparchive.py merge --merged_file new.wpr archive1.wpr archive2.wpr ...
"""

import difflib
import email.utils
import httplib
import httpzlib
import json
import logging
import optparse
import os
import persistentmixin
import StringIO
import subprocess
import sys
import tempfile
import urlparse
from collections import defaultdict

import platformsettings


class HttpArchiveException(Exception):
  """Base class for all exceptions in httparchive."""
  pass


class HttpArchive(dict, persistentmixin.PersistentMixin):
  """Dict with ArchivedHttpRequest keys and ArchivedHttpResponse values.

  PersistentMixin adds the following methods:
    AssertWritable(filename)
    Load(filename)
    Persist(filename)

  Attributes:
    server_rtt: dict of {hostname, server rtt in milliseconds}
  """

  def __init__(self):
    self.server_rtt = {}

  def get_server_rtt(self, server):
    """Retrieves the round trip time (rtt) to the server

    Args:
      server: the hostname of the server

    Returns:
      round trip time to the server in seconds, or 0 if unavailable
    """
    if server not in self.server_rtt:
      # TODO(tonyg): Pinging inline with the request causes timeouts. Need to
      # find a way to restore this functionality.
      self.server_rtt[server] = 0  # platform_settings.ping_rtt(server)
    return self.server_rtt[server]

  def get(self, request, default=None):
    """Return the archived response for a given request.

    Does extra checking for handling some HTTP request headers.

    Args:
      request: instance of ArchivedHttpRequest
      default: default value to return if request is not found

    Returns:
      Instance of ArchivedHttpResponse or default if no matching
      response is found
    """
    if request in self:
      return self[request]
    return self.get_conditional_response(request, default)

  def get_conditional_response(self, request, default):
    """Get the response based on the conditional HTTP request headers.

    Args:
      request: an ArchivedHttpRequest representing the original request.
      default: default ArchivedHttpResponse
          original request with matched headers removed.

    Returns:
      an ArchivedHttpResponse with a status of 200, 302 (not modified), or
          412 (precondition failed)
    """
    response = default
    if request.is_conditional():
      stripped_request = request.create_request_without_conditions()
      if stripped_request in self:
        response = self[stripped_request]
        if response.status == 200:
          status = self.get_conditional_status(request, response)
          if status != 200:
            response = create_response(status)
    return response

  def get_conditional_status(self, request, response):
    status = 200
    last_modified = email.utils.parsedate(
        response.get_header_case_insensitive('last-modified'))
    response_etag = response.get_header_case_insensitive('etag')
    is_get_or_head = request.command.upper() in ('GET', 'HEAD')

    match_value = request.headers.get('if-match', None)
    if match_value:
      if self.is_etag_match(match_value, response_etag):
        status = 200
      else:
        status = 412  # precondition failed
    none_match_value = request.headers.get('if-none-match', None)
    if none_match_value:
      if self.is_etag_match(none_match_value, response_etag):
        status = 304
      elif is_get_or_head:
        status = 200
      else:
        status = 412
    if is_get_or_head and last_modified:
      for header in ('if-modified-since', 'if-unmodified-since'):
        date = email.utils.parsedate(request.headers.get(header, None))
        if date:
          if ((header == 'if-modified-since' and last_modified > date) or
              (header == 'if-unmodified-since' and last_modified < date)):
            if status != 412:
              status = 200
          else:
            status = 304  # not modified
    return status

  def is_etag_match(self, request_etag, response_etag):
    """Determines whether the entity tags of the request/response matches.

    Args:
      request_etag: the value string of the "if-(none)-match:"
                    portion of the request header
      response_etag: the etag value of the response

    Returns:
      True on match, False otherwise
    """
    response_etag = response_etag.strip('" ')
    for etag in request_etag.split(','):
      etag = etag.strip('" ')
      if etag in ('*', response_etag):
        return True
    return False

  def get_requests(self, command=None, host=None, path=None, use_query=True):
    """Return a list of requests that match the given args."""
    return [r for r in self if r.matches(command, host, path,
                                         use_query=use_query)]

  def ls(self, command=None, host=None, path=None):
    """List all URLs that match given params."""
    return ''.join(sorted(
        '%s\n' % r for r in self.get_requests(command, host, path)))

  def cat(self, command=None, host=None, path=None):
    """Print the contents of all URLs that match given params."""
    out = StringIO.StringIO()
    for request in self.get_requests(command, host, path):
      print >>out, str(request)
      print >>out, 'Untrimmed request headers:'
      for k in request.headers:
        print >>out, '    %s: %s' % (k, request.headers[k])
      if request.request_body:
        print >>out, request.request_body
      print >>out, '---- Response Info', '-' * 51
      response = self[request]
      chunk_lengths = [len(x) for x in response.response_data]
      print >>out, ('Status: %s\n'
                    'Reason: %s\n'
                    'Headers delay: %s\n'
                    'Response headers:') % (
          response.status, response.reason, response.delays['headers'])
      for k, v in response.headers:
        print >>out, '    %s: %s' % (k, v)
      print >>out, ('Chunk count: %s\n'
                    'Chunk lengths: %s\n'
                    'Chunk delays: %s') % (
          len(chunk_lengths), chunk_lengths, response.delays['data'])
      body = response.get_data_as_text()
      print >>out, '---- Response Data', '-' * 51
      if body:
        print >>out, body
      else:
        print >>out, '[binary data]'
      print >>out, '=' * 70
    return out.getvalue()

  def stats(self, command=None, host=None, path=None):
    """Print stats about the archive for all URLs that match given params."""
    matching_requests = self.get_requests(command, host, path)
    if not matching_requests:
      print 'Failed to find any requests matching given command, host, path.'
      return

    out = StringIO.StringIO()
    stats = {}
    stats['Total'] = len(matching_requests)
    stats['Domains'] = defaultdict(int)
    stats['HTTP_response_code'] = defaultdict(int)
    stats['content_type'] = defaultdict(int)
    stats['Documents'] = defaultdict(int)
    
    for request in matching_requests:
      stats['Domains'][request.host] += 1
      stats['HTTP_response_code'][self[request].status] += 1
      
      content_type = self[request].get_header('content-type')
      # Remove content type options for readability and higher level groupings.
      str_content_type = str(content_type.split(';')[0] 
                            if content_type else None)
      stats['content_type'][str_content_type] += 1

      #  Documents are the main URL requested and not a referenced resource.
      if str_content_type == 'text/html' and not 'referer' in request.headers:
        stats['Documents'][request.host] += 1
    
    print >>out, json.dumps(stats, indent=4)
    return out.getvalue()

  def merge(self, merged_archive=None, other_archives=None):
    """Merge multiple archives into merged_archive by 'chaining' resources, 
    only resources that are not part of the accumlated archive are added"""
    if not other_archives:
      print 'No archives passed to merge'
      return
    
    # Note we already loaded 'replay_file'. 
    print 'Loaded %d responses' % len(self)

    for archive in other_archives:
      if not os.path.exists(archive):
        print 'Error: Replay file "%s" does not exist' % archive
        return
      
      http_archive_other = HttpArchive.Load(archive)
      print 'Loaded %d responses from %s' % (len(http_archive_other), archive)
      for r in http_archive_other:
        # Only resources that are not already part of the current archive 
        # get added.
        if r not in self:
          print '\t %s ' % r
          self[r] = http_archive_other[r]
    self.Persist('%s' % merged_archive)

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
    tmp_file.write(response.get_response_as_text())
    tmp_file.close()
    subprocess.check_call([editor, tmp_file.name])
    response.set_response_from_text(''.join(open(tmp_file.name).readlines()))
    os.remove(tmp_file.name)

  def find_closest_request(self, request, use_path=False):
    """Find the closest matching request in the archive to the given request.

    Args:
      request: an ArchivedHttpRequest
      use_path: If True, closest matching request's path component must match.
        (Note: this refers to the 'path' component within the URL, not the
         query string component.)
        If use_path=False, candidate will NOT match in example below
        e.g. request   = GET www.test.com/path?aaa
             candidate = GET www.test.com/diffpath?aaa
    Returns:
      If a close match is found, return the instance of ArchivedHttpRequest.
      Otherwise, return None.
    """
    best_match = None
    matcher = difflib.SequenceMatcher(b=request.formatted_request)
    path = None
    if use_path:
      path = request.path
    requests = self.get_requests(request.command, request.host, path,
                                 use_query=not use_path)

    if len(requests) == 1:
      return requests[0]

    for candidate in requests:
      matcher.set_seq1(candidate.formatted_request)
      best_match = max(best_match, (matcher.ratio(), candidate))

    if best_match:
      return best_match[1]
    return None

  def diff(self, request):
    """Diff the given request to the closest matching request in the archive.

    Args:
      request: an ArchivedHttpRequest
    Returns:
      If a close match is found, return a textual diff between the requests.
      Otherwise, return None.
    """
    request_lines = request.formatted_request.split('\n')
    closest_request = self.find_closest_request(request)
    if closest_request:
      closest_request_lines = closest_request.formatted_request.split('\n')
      return '\n'.join(difflib.ndiff(closest_request_lines, request_lines))
    return None


class ArchivedHttpRequest(object):
  """Record all the state that goes into a request.

  ArchivedHttpRequest instances are considered immutable so they can
  serve as keys for HttpArchive instances.
  (The immutability is not enforced.)

  Upon creation, the headers are "trimmed" (i.e. edited or dropped)
  and saved to self.trimmed_headers to allow requests to match in a wider
  variety of playback situations (e.g. using different user agents).

  For unpickling, 'trimmed_headers' is recreated from 'headers'. That
  allows for changes to the trim function and can help with debugging.
  """
  CONDITIONAL_HEADERS = [
      'if-none-match', 'if-match',
      'if-modified-since', 'if-unmodified-since']

  def __init__(self, command, host, path, request_body, headers, is_ssl=False):
    """Initialize an ArchivedHttpRequest.

    Args:
      command: a string (e.g. 'GET' or 'POST').
      host: a host name (e.g. 'www.google.com').
      path: a request path (e.g. '/search?q=dogs').
      request_body: a request body string for a POST or None.
      headers: {key: value, ...} where key and value are strings.
      is_ssl: a boolean which is True iff request is make via SSL.
    """
    self.command = command
    self.host = host
    self.path = path
    self.path_without_query = urlparse.urlparse(path).path
    self.request_body = request_body
    self.headers = headers
    self.is_ssl = is_ssl
    self.trimmed_headers = self._TrimHeaders(headers)
    self.formatted_request = self._GetFormattedRequest()

  def __str__(self):
    scheme = 'https' if self.is_ssl else 'http'
    return '%s %s://%s%s %s' % (
        self.command, scheme, self.host, self.path, self.trimmed_headers)

  def __repr__(self):
    return repr((self.command, self.host, self.path, self.request_body,
                 self.trimmed_headers, self.is_ssl))

  def __hash__(self):
    """Return a integer hash to use for hashed collections including dict."""
    return hash(repr(self))

  def __eq__(self, other):
    """Define the __eq__ method to match the hash behavior."""
    return repr(self) == repr(other)

  def __setstate__(self, state):
    """Influence how to unpickle.

    "headers" are the original request headers.
    "trimmed_headers" are the trimmed headers used for matching requests
    during replay.

    Args:
      state: a dictionary for __dict__
    """
    if 'full_headers' in state:
      # Fix older version of archive.
      state['headers'] = state['full_headers']
      del state['full_headers']
    if 'headers' not in state:
      raise HttpArchiveException(
          'Archived HTTP request is missing "headers". The HTTP archive is'
          ' likely from a previous version and must be re-recorded.')
    state['trimmed_headers'] = self._TrimHeaders(dict(state['headers']))
    if 'is_ssl' not in state:
      state['is_ssl'] = False
    self.__dict__.update(state)
    self.path_without_query = urlparse.urlparse(self.path).path
    self.formatted_request = self._GetFormattedRequest()

  def __getstate__(self):
    """Influence how to pickle.

    Returns:
      a dict to use for pickling
    """
    state = self.__dict__.copy()
    del state['trimmed_headers']
    del state['path_without_query']
    del state['formatted_request']
    return state

  def _GetFormattedRequest(self):
    """Format request to make diffs easier to read.

    Returns:
      A string consisting of the request. Example:
      'GET www.example.com/path\nHeader-Key: header value\n'
    """
    parts = ['%s %s%s\n' % (self.command, self.host, self.path)]
    if self.request_body:
      parts.append('%s\n' % self.request_body)
    for k, v in self.trimmed_headers:
      k = '-'.join(x.capitalize() for x in k.split('-'))
      parts.append('%s: %s\n' % (k, v))
    return ''.join(parts)

  def matches(self, command=None, host=None, path_with_query=None,
              use_query=True):
    """Returns true iff the request matches all parameters.

    Args:
      command: a string (e.g. 'GET' or 'POST').
      host: a host name (e.g. 'www.google.com').
      path_with_query: a request path with query string (e.g. '/search?q=dogs')
      use_query:
        If use_query is True, request matching uses both the hierarchical path
        and query string component.
        If use_query is False, request matching only uses the hierarchical path

        e.g. req1 = GET www.test.com/index?aaaa
             req2 = GET www.test.com/index?bbbb

        If use_query is True, req1.matches(req2) evaluates to False
        If use_query is False, req1.matches(req2) evaluates to True

    Returns:
      True iff the request matches all parameters
    """
    if command is not None and command != self.command:
      return False
    if host is not None and host != self.host:
      return False
    if path_with_query is None:
      return True
    if use_query:
      return path_with_query == self.path
    else:
      return self.path_without_query == urlparse.urlparse(path_with_query).path

  @classmethod
  def _TrimHeaders(cls, headers):
    """Removes headers that are known to cause problems during replay.

    These headers are removed for the following reasons:
    - accept: Causes problems with www.bing.com. During record, CSS is fetched
              with *. During replay, it's text/css.
    - accept-charset, accept-language, referer: vary between clients.
    - connection, method, scheme, url, version: Cause problems with spdy.
    - cookie: Extremely sensitive to request/response order.
    - keep-alive: Not supported by Web Page Replay.
    - user-agent: Changes with every Chrome version.
    - proxy-connection: Sent for proxy requests.

    Another variant to consider is dropping only the value from the header.
    However, this is particularly bad for the cookie header, because the
    presence of the cookie depends on the responses we've seen when the request
    is made.

    Args:
      headers: {header_key: header_value, ...}

    Returns:
      [(header_key, header_value), ...]  # (with undesirable headers removed)
    """
    # TODO(tonyg): Strip sdch from the request headers because we can't
    # guarantee that the dictionary will be recorded, so replay may not work.
    if 'accept-encoding' in headers:
      headers['accept-encoding'] = headers['accept-encoding'].replace(
          'sdch', '')
      # A little clean-up
      if headers['accept-encoding'].endswith(','):
        headers['accept-encoding'] = headers['accept-encoding'][:-1]
    undesirable_keys = [
        'accept', 'accept-charset', 'accept-language',
        'connection', 'cookie', 'keep-alive', 'method',
        'referer', 'scheme', 'url', 'version', 'user-agent', 'proxy-connection',
        'x-chrome-variations']
    return sorted([(k, v) for k, v in headers.items()
                   if k.lower() not in undesirable_keys])

  def is_conditional(self):
    """Return list of headers that match conditional headers."""
    for header in self.CONDITIONAL_HEADERS:
      if header in self.headers:
        return True
    return False

  def create_request_without_conditions(self):
    stripped_headers = dict((k, v) for k, v in self.headers.iteritems()
                            if k.lower() not in self.CONDITIONAL_HEADERS)
    return ArchivedHttpRequest(
        self.command, self.host, self.path, self.request_body,
        stripped_headers, self.is_ssl)

class ArchivedHttpResponse(object):
  """All the data needed to recreate all HTTP response."""

  # CHUNK_EDIT_SEPARATOR is used to edit and view text content.
  # It is not sent in responses. It is added by get_data_as_text()
  # and removed by set_data().
  CHUNK_EDIT_SEPARATOR = '[WEB_PAGE_REPLAY_CHUNK_BOUNDARY]'

  # DELAY_EDIT_SEPARATOR is used to edit and view server delays.
  DELAY_EDIT_SEPARATOR = ('\n[WEB_PAGE_REPLAY_EDIT_ARCHIVE --- '
                          'Delays are above. Response content is below.]\n')

  def __init__(self, version, status, reason, headers, response_data,
               delays=None):
    """Initialize an ArchivedHttpResponse.

    Args:
      version: HTTP protocol version used by server.
          10 for HTTP/1.0, 11 for HTTP/1.1 (same as httplib).
      status: Status code returned by server (e.g. 200).
      reason: Reason phrase returned by server (e.g. "OK").
      headers: list of (header, value) tuples.
      response_data: list of content chunks.
          Concatenating the chunks gives the complete contents
          (i.e. the chunks do not have any lengths or delimiters).
          Do not include the final, zero-length chunk that marks the end.
      delays: dict of (ms) delays before "headers" and "data". For example,
          {'headers': 50, 'data': [0, 10, 10]}
    """
    self.version = version
    self.status = status
    self.reason = reason
    self.headers = headers
    self.response_data = response_data
    self.delays = delays
    self.fix_delays()

  def fix_delays(self):
    """Initialize delays, or check the number of data delays."""
    expected_num_delays = len(self.response_data)
    if not self.delays:
      self.delays = {
          'headers': 0,
          'data': [0] * expected_num_delays
          }
    else:
      num_delays = len(self.delays['data'])
      if num_delays != expected_num_delays:
        raise HttpArchiveException(
            'Server delay length mismatch: %d (expected %d): %s',
            num_delays, expected_num_delays, self.delays['data'])

  def __repr__(self):
    return repr((self.version, self.status, self.reason, sorted(self.headers),
                 self.response_data))

  def __hash__(self):
    """Return a integer hash to use for hashed collections including dict."""
    return hash(repr(self))

  def __eq__(self, other):
    """Define the __eq__ method to match the hash behavior."""
    return repr(self) == repr(other)

  def __setstate__(self, state):
    """Influence how to unpickle.

    Args:
      state: a dictionary for __dict__
    """
    if 'server_delays' in state:
      state['delays'] = {
          'headers': 0,
          'data': state['server_delays']
          }
      del state['server_delays']
    elif 'delays' not in state:
      state['delays'] = None
    self.__dict__.update(state)
    self.fix_delays()

  def get_header(self, key, default=None):
    for k, v in self.headers:
      if key == k:
        return v
    return default

  def get_header_case_insensitive(self, key):
    for k, v in self.headers:
      if key.lower() == k.lower():
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

  def is_chunked(self):
    return self.get_header('transfer-encoding') == 'chunked'

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

  def get_delays_as_text(self):
    """Return delays as editable text."""
    return json.dumps(self.delays, indent=2)

  def get_response_as_text(self):
    """Returns response content as a single string.

    Server delays are separated on a per-chunk basis. Delays are in seconds.
    Response content begins after DELAY_EDIT_SEPARATOR
    """
    data = self.get_data_as_text()
    if data is None:
      logging.warning('Data can not be represented as text.')
      data = ''
    delays = self.get_delays_as_text()
    return self.DELAY_EDIT_SEPARATOR.join((delays, data))

  def set_data(self, text):
    """Inverse of get_data_as_text().

    Split on CHUNK_EDIT_SEPARATOR and compress if needed.
    """
    text_chunks = text.split(self.CHUNK_EDIT_SEPARATOR)
    if self.is_compressed():
      self.response_data = httpzlib.compress_chunks(text_chunks, self.is_gzip())
    else:
      self.response_data = text_chunks
    if not self.is_chunked():
      content_length = sum(len(c) for c in self.response_data)
      self.set_header('content-length', str(content_length))

  def set_delays(self, delays_text):
    """Inverse of get_delays_as_text().

    Args:
      delays_text: JSON encoded text such as the following:
          {
            headers: 80,
            data: [6, 55, 0]
          }
        Times are in milliseconds.
        Each data delay corresponds with one response_data value.
    """
    try:
      self.delays = json.loads(delays_text)
    except (ValueError, KeyError) as e:
      logging.critical('Unable to parse delays %s: %s', delays_text, e)
    self.fix_delays()

  def set_response_from_text(self, text):
    """Inverse of get_response_as_text().

    Modifies the state of the archive according to the textual representation.
    """
    try:
      delays, data = text.split(self.DELAY_EDIT_SEPARATOR)
    except ValueError:
      logging.critical(
          'Error parsing text representation. Skipping edits.')
      return
    self.set_delays(delays)
    self.set_data(data)


def create_response(status, reason=None, headers=None, body=None):
  """Convenience method for creating simple ArchivedHttpResponse objects."""
  if reason is None:
    reason = httplib.responses.get(status, 'Unknown')
  if headers is None:
    headers = [('content-type', 'text/plain')]
  if body is None:
    body = "%s %s" % (status, reason)
  return ArchivedHttpResponse(11, status, reason, headers, [body])


def main():
  class PlainHelpFormatter(optparse.IndentedHelpFormatter):
    def format_description(self, description):
      if description:
        return description + '\n'
      else:
        return ''

  option_parser = optparse.OptionParser(
      usage='%prog [ls|cat|edit|stats|merge] [options] replay_file(s)',
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
  option_parser.add_option('-f', '--merged_file', default=None,
        action='store',
        type='string',
        help='The output file to use when using the merge command.')

  options, args = option_parser.parse_args()

  # Merge command expects an umlimited number of archives.
  if len(args) < 2:
    print 'args: %s' % args
    option_parser.error('Must specify a command and replay_file')

  command = args[0]
  replay_file = args[1]

  if not os.path.exists(replay_file):
    option_parser.error('Replay file "%s" does not exist' % replay_file)

  http_archive = HttpArchive.Load(replay_file)
  if command == 'ls':
    print http_archive.ls(options.command, options.host, options.path)
  elif command == 'cat':
    print http_archive.cat(options.command, options.host, options.path)
  elif command == 'stats':
    print http_archive.stats(options.command, options.host, options.path)
  elif command == 'merge':
    if not options.merged_file:
      print 'Error: Must specify a merged file name (use --merged_file)'
      return
    http_archive.merge(options.merged_file, args[2:])
  elif command == 'edit':
    http_archive.edit(options.command, options.host, options.path)
    http_archive.Persist(replay_file)
  else:
    option_parser.error('Unknown command "%s"' % command)
  return 0


if __name__ == '__main__':
  sys.exit(main())

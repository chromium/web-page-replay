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

import difflib
import email.utils
import httpzlib
import logging
import optparse
import os
import persistentmixin
import StringIO
import subprocess
import tempfile
import urlparse

import platformsettings


class HttpArchiveException(Exception):
  """Base class for all exceptions in httparchive."""
  pass


class HttpArchive(dict, persistentmixin.PersistentMixin):
  """Dict with ArchivedHttpRequest keys and ArchivedHttpResponse values.

  PersistentMixin adds CreateNew(filename), Load(filename), and Persist().

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
      platform_settings = platformsettings.get_platform_settings()
      self.server_rtt[server] = platform_settings.ping(server)
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

    logging.debug('Checking headers for: %s', request)

    # Note: order matters! headers are checked in-order specified
    #       by conditional_headers.
    #       etag headers must be checked before non etag headers
    # if-(none)-match should come first; from RFC 2068:
    #   "If the request would, without the if-(none)-match header field,
    #    result in anything other than a 2xx status,
    #    then the if-(none)-match header MUST be ignored."
    conditional_headers = [
        'if-none-match', 'if-match',
        'if-modified-since', 'if-unmodified-since']

    matched_conditional_headers = [h for h in conditional_headers
                                   if h in request.headers]

    response = default
    if matched_conditional_headers:
      shortened_headers = dict((k, v) for k, v in request.headers.iteritems()
                               if k.lower() not in conditional_headers)
      # The request with conditional headers removed.
      shortened_request = ArchivedHttpRequest(
          request.command, request.host, request.path,
          request.request_body, shortened_headers, request.is_ssl)
      if shortened_request in self:
        status, reason = self.handle_conditional_headers(
            matched_conditional_headers, request, shortened_request)
        if status == 200:
          response = self[shortened_request]
        else:
          response = self.create_response(status, reason)
        logging.debug('Checked headers, returning with %s, %s', status, reason)
    return response

  def handle_conditional_headers(self, matched_conditional_headers,
                       request, shortened_request):
    """Handles HTTP request headers properly.

    Args:
      matched_conditional_headers: headers to handle within the given request
      request: Instance of ArchivedHttpRequest representing the original request
      shortened_request: Instance of ArchivedHttpRequest representing the
        original request with matched headers removed.

    Returns:
      Tuple of (status, reason) of the appropriate HTTP response
    """
    status, reason = 200, 'OK'
    response = self[shortened_request]

    last_modified_string = self.get_header_case_insensitive(
        response.headers, 'last-modified')
    last_modified = email.utils.parsedate(last_modified_string)
    etag_response = self.get_header_case_insensitive(response.headers, 'etag')

    for header in matched_conditional_headers:
      if header == 'if-match':
        etag_request = request.headers[header]
        if self.entity_tag_match(etag_request, etag_response):
          status, reason = 200, 'OK'
        else:
          status, reason = 412, 'Precondition Failed'
      elif header == 'if-none-match':
        etag_request = request.headers[header]
        if self.entity_tag_match(etag_request, etag_response):
          status, reason = 412, 'Precondition Failed'
        else:
          status, reason = 200, 'OK'
      elif header in ('if-modified-since', 'if-unmodified-since'):
        date_string = request.headers[header]
        date = email.utils.parsedate(date_string)
        # Only do checks for GET or HEAD requests (as per RFC)
        if ((request.command.upper() not in ('GET', 'HEAD')) or
            date is None or last_modified is None):
          # Improperly formatted string; ignore header
          continue
        if ((header == 'if-modified-since' and last_modified > date) or
            (header == 'if-unmodified-since' and last_modified < date)):
          # Only update the status if etag check succeeds
          if not status == 412:
            status, reason = 200, 'OK'
          continue
        status, reason = 304, 'Not Modified'

    return status, reason

  def entity_tag_match(self, etag_request, etag_response):
    """Determines whether the entity tags of the request/response matches.

    Args:
      etag_request: the value string of the "if-(none)-match:"
                    portion of the request header
      etag_response: the etag value of the response

    Returns:
      True on match, False otherwise
    """
    etag_response = etag_response.strip('" ')
    for etag in etag_request.split(','):
      etag = etag.strip('" ')
      if etag in ('*', etag_response):
        return True
    return False

  def get_header_case_insensitive(self, headers, key):
    """Returns the specified key from a list of (key, value) tuples.

    Args:
      headers: a list of tuples
      key: the key we want to search for in the list

    Returns:
      the value corresponding to the key if found, None otherwise
    """
    for k, v in headers:
      if k.lower() == key.lower():
        return v
    return None

  def create_response(self, status, reason):
    headers = [
        ('content-type', 'text/plain'),
        ('content-length', str(len(reason))),
    ]
    return ArchivedHttpResponse(11, status, reason, headers, reason)

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
      print >>out, '%s %s %s\nrequest headers:\n' % (
          request.command, request.host, request.path)
      for k in request.headers:
        print >>out, '    %s: %s' % (k, request.headers[k])
      if request.request_body:
        print >>out, request.request_body
      print >>out, '-' * 70
      response = self[request]
      print >>out, 'Status: %s\nReason: %s\nheaders:\n' % (
          response.status, response.reason)
      for k, v in response.headers:
        print >>out, '    %s: %s' % (k, v)
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
    tmp_file.write(response.get_response_as_text())
    tmp_file.close()
    subprocess.check_call([editor, tmp_file.name])
    response.set_response_from_text(''.join(open(tmp_file.name).readlines()))
    os.remove(tmp_file.name)

  def _format_request_lines(self, req):
    """Format request to make diffs easier to read.

    Args:
      req: an ArchivedHttpRequest
    Returns:
      Example:
      ['GET www.example.com/path\n', 'Header-Key: header value\n', ...]
    """
    parts = ['%s %s%s\n' % (req.command, req.host, req.path)]
    if req.request_body:
      parts.append('%s\n' % req.request_body)
    for k, v in req.trimmed_headers:
      k = '-'.join(x.capitalize() for x in k.split('-'))
      parts.append('%s: %s\n' % (k, v))
    return parts

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
    request_lines = self._format_request_lines(request)
    matcher = difflib.SequenceMatcher(b=''.join(request_lines))
    path = None
    if use_path:
      path = request.path
    for candidate in self.get_requests(request.command, request.host, path,
                                       use_query=not use_path):
      candidate_lines = self._format_request_lines(candidate)
      matcher.set_seq1(''.join(candidate_lines))
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
    request_lines = self._format_request_lines(request)
    closest_request = self.find_closest_request(request)
    if closest_request:
      closest_request_lines = self._format_request_lines(closest_request)
      return ''.join(difflib.ndiff(closest_request_lines, request_lines))
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
    self.request_body = request_body
    self.headers = headers
    self.is_ssl = is_ssl
    self.trimmed_headers = self._TrimHeaders(headers)

  def __str__(self):
    scheme = 'https' if self.is_ssl else 'http'
    return '%s %s://%s%s %s' % (self.command, scheme, self.host, self.path,
                                self.trimmed_headers)

  def verbose(self):
    return '%s %s%s %s' % (self.command, self.host, self.path, self.headers)

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

  def __getstate__(self):
    """Influence how to pickle.

    Returns:
      a dict to use for pickling
    """
    state = self.__dict__.copy()
    del state['trimmed_headers']
    return state

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
    path_match = path_with_query == self.path
    if not use_query:
      self_path = urlparse.urlparse('http://%s%s' % (
          self.host or '', self.path or '')).path
      other_path = urlparse.urlparse('http://%s%s' % (
          host or '', path_with_query or '')).path
      path_match = self_path == other_path
    return ((command is None or command == self.command) and
            (host is None or host == self.host) and
            (path_with_query is None or path_match))

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
        'referer', 'scheme', 'url', 'version', 'user-agent', 'proxy-connection']
    return sorted([(k, v) for k, v in headers.items()
                   if k.lower() not in undesirable_keys])


class ArchivedHttpResponse(object):
  """All the data needed to recreate all HTTP response."""

  # CHUNK_EDIT_SEPARATOR is used to edit and view text content.
  # It is not sent in responses. It is added by get_data_as_text()
  # and removed by set_data().
  CHUNK_EDIT_SEPARATOR = '[WEB_PAGE_REPLAY_CHUNK_BOUNDARY]'

  # SERVER_DELAY_EDIT_SEPARATOR is used to edit and view server delays.
  DELAY_EDIT_SEPARATOR = ('\n[WEB_PAGE_REPLAY_EDIT_ARCHIVE '
                          '--- Server delays per chunk are shown above. '
                          'Response content is below.]\n')

  def __init__(self, version, status, reason, headers, response_data,
               server_delays=None):
    """Initialize an ArchivedHttpResponse.

    Args:
      version: HTTP protocol version used by server.
          10 for HTTP/1.0, 11 for HTTP/1.1 (same as httplib).
      status: Status code returned by server (e.g. 200).
      reason: Reason phrase returned by server (e.g. "OK").
      headers: list of (header, value) tuples.
      response_data: list of content chunks where concatenating the chunks gives
          the complete contents (i.e. the chunks do not have any lengths or
          delimiters).
          Must not include the last 'sentinel' chunk (i.e. the zero-length chunk
          with no data, to mark termination of data transfer).
      server_delays: list of server delays for each chunk. Note that
          if chunked encoding is used, this will also record the ttfb for the
          last 'sentinel' chunk (zero-length chunk with no data).
    """
    self.version = version
    self.status = status
    self.reason = reason
    self.headers = headers
    self.response_data = response_data
    self.server_delays = server_delays
    self.fix_chunk_delays()

  def fix_chunk_delays(self):
    """Checks whether the number of server delays match the number of chunks.

    If they do not match, either zeroes are appended or values truncated from
    server_delays.
    """
    issue_warning = True
    if not self.server_delays:
      self.server_delays = []
      issue_warning = False
    server_delays = self.server_delays

    use_chunked = 'transfer-encoding' in self.headers
    # If we are using chunked encoding, subtract the offset for the 'sentinel'
    # chunk.
    server_delay_offset = 1 if use_chunked else 0

    proper_server_delays_length = len(self.response_data) + server_delay_offset
    length_delta = proper_server_delays_length - len(server_delays)
    if length_delta < 0:
      if issue_warning:
        logging.warning('Server_delay contains too many elements; '
                        'truncating %d elements', abs(length_delta))
      del server_delays[proper_server_delays_length:]
    elif length_delta > 0:
      if issue_warning:
        logging.warning('Server_delay contains too few elements; '
                        'appending %d elements', length_delta)
      server_delays += [0] * length_delta

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
    if 'server_delays' not in state:
      state['server_delays'] = []
    self.__dict__.update(state)
    self.fix_chunk_delays()

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

  def get_server_delays_as_text(self):
    """Return server delays as multiple lines of numbers, one per line.

    e.g.
    10.0000
    2.3211
    1.5324
    5.300

    Returns 0 for each chunk for archives without server_delay data.
    """
    return '\n'.join('%s' % delay for delay in self.server_delays)

  def get_response_as_text(self):
    """Returns response content as a single string.

    Server delays are separated on a per-chunk basis. Delays are in seconds.
    Response content begins after DELAY_EDIT_SEPARATOR
    """
    data = self.get_data_as_text()
    if data is None:
      logging.warning('Data can not be represented as text.')
      data = ''
    server_delays = self.get_server_delays_as_text()
    return self.DELAY_EDIT_SEPARATOR.join((server_delays, data))

  def set_data(self, text):
    """Inverse of get_data_as_text().

    Split on CHUNK_EDIT_SEPARATOR and compress if needed.
    """
    text_chunks = text.split(self.CHUNK_EDIT_SEPARATOR)
    if self.is_compressed():
      self.response_data = httpzlib.compress_chunks(text_chunks, self.is_gzip())
    else:
      self.response_data = text_chunks
    if not self.get_header('transfer-encoding'):
      content_length = sum(len(c) for c in self.response_data)
      self.set_header('content-length', str(content_length))

  def set_server_delays(self, delays_text):
    """Inverse of get_server_delays_as_text().

    Sets the server delay of each to its corresponding textual representation.
    If the delays_text can not be parsed, a default value of 0 is assumed.

    This method does not enforce that the number of chunk delays matches the
    number of chunks!

    Args:
      delays_text: server delays as multiple lines of numbers, one per line.

      e.g.
      10.0000
      2.3211
      1.5324
      5.300
    """
    server_delays = []
    for delay_str in delays_text.split('\n'):
      delay = 0
      try:
        delay = float(delay_str)
      except ValueError, e:
        logging.critical('Unable to parse server delay %s: %s', delay_str, e)
      server_delays.append(delay)
    self.server_delays = server_delays
    self.fix_chunk_delays()

  def set_response_from_text(self, text):
    """Inverse of get_response_as_text().

    Modifies the state of the archive according to the textual representation.
    """
    partitions = text.split(self.DELAY_EDIT_SEPARATOR)
    if not len(partitions) == 2:
      logging.critical('Error parsing text representation. '
                       'Edits will not be saved.')
      return
    self.set_server_delays(partitions[0])
    self.set_data(partitions[1])


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

  http_archive = HttpArchive.Load(replay_file)
  if command == 'ls':
    print http_archive.ls(options.command, options.host, options.path)
  elif command == 'cat':
    print http_archive.cat(options.command, options.host, options.path)
  elif command == 'edit':
    http_archive.edit(options.command, options.host, options.path)
    http_archive.Persist(replay_file)
  else:
    option_parser.error('Unknown command "%s"' % command)

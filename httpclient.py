#!/usr/bin/env python
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Retrieve web resources over http."""

import httparchive
import httplib
import logging

class DetailedHTTPResponse(httplib.HTTPResponse):
  """Preserve details relevant to replaying responses.

  WARNING: This code uses attributes and methods of HTTPResponse
  that are not part of the public interface.
  """

  def read_chunks(self):
    """Return an array of data.

    The returned chunked have the chunk size and CRLFs stripped off.
    If the response was compressed, the returned data is still compressed.

    Returns:
      [response_body]  # non-chunked responses
      [response_body_chunk_1, response_body_chunk_2, ...]  # chunked responses
    """
    buf = []
    if not self.chunked:
      chunks = [self.read()]
    else:
      try:
        chunks = []
        while True:
          line = self.fp.readline()
          chunk_size = self._read_chunk_size(line)
          if chunk_size is None:
            raise httplib.IncompleteRead(''.join(chunks))
          if chunk_size == 0:
            break
          chunks.append(self._safe_read(chunk_size))
          self._safe_read(2)  # skip the CRLF at the end of the chunk

        # Ignore any trailers.
        while True:
          line = self.fp.readline()
          if not line or line == '\r\n':
            break
      finally:
        self.close()
    return chunks

  @classmethod
  def _read_chunk_size(cls, line):
    chunk_extensions_pos = line.find(';')
    if chunk_extensions_pos != -1:
      line = line[:extention_pos]  # strip chunk-extensions
    try:
      chunk_size = int(line, 16)
    except ValueError:
      return None
    return chunk_size


class DetailedHTTPConnection(httplib.HTTPConnection):
  """Preserve details relevant to replaying connections."""
  response_class = DetailedHTTPResponse


class RealHttpFetch(object):
  def __init__(self, real_dns_lookup):
    self._real_dns_lookup = real_dns_lookup

  def __call__(self, request, headers):
    """Fetch an HTTP request and return the response and response_body.

    Args:
      request: an instance of an ArchivedHttpRequest
      headers: a dict of HTTP headers
    Returns:
      (instance of httplib.HTTPResponse,
       [response_body_chunk_1, response_body_chunk_2, ...])
      # If the response did not use chunked encoding, there is only one chunk.
    """
    # TODO(tonyg): Strip sdch from the request headers because we can't
    # guarantee that the dictionary will be recorded, so replay may not work.
    if 'accept-encoding' in headers:
      headers['accept-encoding'] = headers['accept-encoding'].replace(
          'sdch', '')

    logging.debug('RealHttpRequest: %s %s', request.host, request.path)
    host_ip = self._real_dns_lookup(request.host)
    if not host_ip:
      logging.critical('Unable to find host ip for name: %s', request.host)
      return None, None
    try:
      connection = DetailedHTTPConnection(host_ip)
      connection.request(
          request.command,
          request.path,
          request.request_body,
          headers)
      response = connection.getresponse()
      chunks = response.read_chunks()
      return response, chunks
    except Exception, e:
      logging.critical('Could not fetch %s: %s', request, e)
      import traceback
      logging.critical(traceback.format_exc())
      return None, None


class RecordHttpArchiveFetch(object):
  """Make real HTTP fetches and save responses in the given HttpArchive."""

  def __init__(self, http_archive, real_dns_lookup, use_deterministic_script):
    """Initialize RecordHttpArchiveFetch.

    Args:
      http_archve: an instance of a HttpArchive
      real_dns_lookup: a function that resolves a host to an IP.
      use_deterministic_script: If True, attempt to inject a script,
        when appropriate, to make JavaScript more deterministic.
    """
    self.http_archive = http_archive
    self.real_http_fetch = RealHttpFetch(real_dns_lookup)
    self.use_deterministic_script = use_deterministic_script

  def __call__(self, request, request_headers):
    """Fetch the request and return the response.

    Args:
      request: an instance of an ArchivedHttpRequest.
      request_headers: a dict of HTTP headers.
    """
    response, response_chunks = self.real_http_fetch(request, request_headers)
    if response is None:
      return None
    archived_http_response = httparchive.ArchivedHttpResponse(
        response.version,
        response.status,
        response.reason,
        response.getheaders(),
        response_chunks)
    if self.use_deterministic_script:
      try:
        archived_http_response.inject_deterministic_script()
      except httparchive.InjectionFailedException as err:
        logging.error('Failed to inject deterministic script for %s', request)
        logging.debug('Request content: %s', err.text)
    logging.debug('Recorded: %s', request)
    self.http_archive[request] = archived_http_response
    return archived_http_response


class ReplayHttpArchiveFetch(object):
  """Serve responses from the given HttpArchive."""

  def __init__(self, http_archive, use_diff_on_unknown_requests=False):
    """Initialize ReplayHttpArchiveFetch.

    Args:
      http_archve: an instance of a HttpArchive
      use_diff_on_unknown_requests: If True, log unknown requests
        with a diff to requests that look similar.
    """
    self.http_archive = http_archive
    self.use_diff_on_unknown_requests = use_diff_on_unknown_requests

  def __call__(self, request, request_headers=None):
    """Fetch the request and return the response.

    Args:
      request: an instance of an ArchivedHttpRequest.
      request_headers: a dict of HTTP headers.
    """
    response = self.http_archive.get(request)
    if not response:
      if self.use_diff_on_unknown_requests:
        reason = self.http_archive.diff(request) or request
      else:
        reason = request
      logging.warning('Could not replay: %s', reason)
    return response

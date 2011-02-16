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
      [content]                # non-chunked responses
      [chunk_1, chunk_2, ...]  # chunked responses
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


class RealHttpRequest(object):
  def __init__(self, real_dns_lookup):
    self._real_dns_lookup = real_dns_lookup

  def __call__(self, request, headers):
    # TODO(tonyg): Strip sdch from the request headers because we can't
    # guarantee that the dictionary will be recorded, so replay may not work.
    if 'accept-encoding' in headers:
      headers['accept-encoding'] = headers['accept-encoding'].replace(
          'sdch', '')

    logging.debug('RealHttpRequest: %s %s', request.host, request.path)
    host_ip = self._real_dns_lookup(request.host)
    if not host_ip:
      logging.critical('Unable to find host ip for name: %s', request.host)
      return None
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
      return None

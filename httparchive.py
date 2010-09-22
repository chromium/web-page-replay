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


class HttpArchive(dict):
  """Dict with ArchivedHttpRequest keys and ArchivedHttpResponse values."""
  pass


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


if __name__ == '__main__':
  import sys
  import cPickle
  import gzip
  import StringIO
  wpr_file = sys.argv[1]
  http_archive = cPickle.load(open(wpr_file))
  for request in http_archive.keys():
    print request.command, request.host, request.path, request.request_body
    print '-' * 70
    response = http_archive[request]
    print 'Status:', response.status
    print 'Reason:', response.reason
    print 'headers:', response.headers
    headers = dict(response.headers)
    if headers.get('content-type', '').startswith('text/'):
      print '-' * 70
      if headers.get('content-encoding', '') == 'gzip':
        compressed_response_data = StringIO.StringIO(response.response_data)
        print gzip.GzipFile(fileobj=compressed_response_data).read()
      else:
        print response.response_data
    print '=' * 70

#!/usr/bin/env python
# Copyright 2015 Google Inc. All Rights Reserved.
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


import httplib
import httpproxy
import threading
import time
import unittest
import util


class MockCustomResponseHandler(object):
  def handle(self, request):
    return None


class MockHttpArchiveFetch(object):
  def __init__(self):
    self.is_record_mode = False

  def __call__(self, request):
    return None


class MockHttpArchiveHandler(httpproxy.HttpArchiveHandler):
  def handle_one_request(self):
    httpproxy.HttpArchiveHandler.handle_one_request(self)
    HttpProxyTest.HANDLED_REQUEST_COUNT += 1


class HttpProxyTest(unittest.TestCase):
  def setUp(self):
    HttpProxyTest.HANDLED_REQUEST_COUNT = 0
    self.host = 'localhost'
    self.port = 8889
    custom_handlers = MockCustomResponseHandler()
    http_archive_fetch = MockHttpArchiveFetch()
    self.proxy_server = httpproxy.HttpProxyServer(
        http_archive_fetch, custom_handlers, host=self.host, port=self.port)
    self.proxy_server.RequestHandlerClass = MockHttpArchiveHandler

  def tearDown(self):
    self.proxy_server.shutdown()

  def serve_requests_forever(self):
    self.proxy_server.serve_forever(poll_interval=0.01)

  # Tests that handle_one_request does not leak threads, and does not try to
  # re-handle connections that are finished.
  def test_handle_one_request_closes_connection(self):
    t = threading.Thread(
        target=HttpProxyTest.serve_requests_forever, args=(self,))
    t.start()

    initial_thread_count = threading.activeCount()

    # Make a bunch of requests.
    request_count = 10
    for _ in range(request_count):
      conn = httplib.HTTPConnection('localhost', 8889, timeout=10)
      conn.request("HEAD","/index.html")
      res = conn.getresponse().read()
      self.assertEqual(len(res), 0)

    # Check to make sure that there is no leak thread.
    util.WaitFor(lambda: threading.activeCount() == initial_thread_count, 1)

    self.assertEqual(request_count, HttpProxyTest.HANDLED_REQUEST_COUNT)


if __name__ == '__main__':
  unittest.main()

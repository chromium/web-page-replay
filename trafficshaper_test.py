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

import dnsproxy
import httparchive
import httpproxy
import logging
import multiprocessing
import sys
import time
import trafficshaper
import unittest
import urllib

import third_party
import dns.resolver


TEST_DNS_HOST = '127.0.0.1'
TEST_DNS_NAMESERVER = '127.0.0.1'
TEST_DNS_PORT = 5555
TEST_HTTP_HOST = '127.0.0.1'
TEST_HTTP_PORT = 8888
TEST_URL = 'http://%s:%s' % (TEST_HTTP_HOST, TEST_HTTP_PORT)

# from timeit.py
if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    DEFAULT_TIMER = time.clock
else:
    # On most other platforms the best timer is time.time()
    DEFAULT_TIMER = time.time


class IntervalTimer:
  def __init__(self, timer=DEFAULT_TIMER):
    self.timer = timer
    self.times = None
    self.names = []

  def start(self):
    self.times = [self.timer()]

  def interval(self, name):
    self.times.append(self.timer())
    self.names.append(name)

  def intervals(self):
    return zip(self.names,
               [self.times[x + 1] - self.times[x]
                for x in range(len(self.times) - 1)])

  def __str__(self):
    return str([(n, "%dms" % (v * 1000)) for n, v in self.intervals()])


class TestDnsProxyServer(dnsproxy.DnsProxyServer):

  def __init__(self, interval_timer):
    dnsproxy.DnsProxyServer.__init__(self,
        use_forwarding=False,
        passthrough_filter=None,
        host=TEST_DNS_HOST,
        port=TEST_DNS_PORT)
    self.interval_timer = interval_timer

  def close_request(self, request):
    dnsproxy.DnsProxyServer.close_request(self, request)
    self.interval_timer.interval("dns proxy server finished")


class TestResolver(object):
  def __init__(self, hostname='example.com'):
    self.resolver = dns.resolver.get_default_resolver()
    self.hostname = hostname

  def __call__(self):
    self.resolver.nameservers = [TEST_DNS_NAMESERVER]
    self.resolver.port = TEST_DNS_PORT
    hostname = self.hostname
    try:
      answers = self.resolver.query(hostname, 'A')
    except (dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.Timeout) as ex:
      logging.debug('TestResolver(%s) -> None (%s)',
                    hostname, ex.__class__.__name__)
      return None
    if answers:
      ip = str(answers[0])
    else:
      ip = None
    return ip


def test_resolve(host, sleep_time):
  resolver = TestResolver(hostname=host)
  time.sleep(sleep_time)
  ip = resolver()


class MockHttpArchiveFetch:
  def __init__(self, interval_timer, num_bytes):
    self.interval_timer = interval_timer
    self.num_bytes = num_bytes
    self.data = ['\x00' * self.num_bytes]

  def __call__(self, request, request_headers=None):
    self.interval_timer.interval("http request received")
    response = httparchive.ArchivedHttpResponse(
        version=11,
        status=200,
        reason='OK',
        headers=[],
        response_data=self.data)
    return response


class TestWebProxyServer(httpproxy.HttpProxyServer):
  def __init__(self, interval_timer, num_bytes):
    http_archive_fetch = MockHttpArchiveFetch(interval_timer, num_bytes)
    httpproxy.HttpProxyServer.__init__(
        self, http_archive_fetch, host=TEST_HTTP_HOST, port=TEST_HTTP_PORT)


class TestTrafficShaper(trafficshaper.TrafficShaper):
  def __init__(self, interval_timer, **kwargs):
    self.interval_timer = interval_timer
    trafficshaper.TrafficShaper.__init__(
        self, host=TEST_HTTP_HOST, port=str(TEST_HTTP_PORT),
        dns_port=str(TEST_DNS_PORT), **kwargs)

  def __enter__(self):
    trafficshaper.TrafficShaper.__enter__(self)
    self.platformsettings.ipfw('show')
    self.interval_timer.start()

  def __exit__(self, *args):
    self.interval_timer.interval("end")
    logging.warn('Interval times: %s', self.interval_timer)
    trafficshaper.TrafficShaper.__exit__(self, *args)


class TrafficShaperTest(unittest.TestCase):
  def setUp(self):
    self.interval_timer = IntervalTimer()

  def testResolve(self):
    num_requests = 5
    sleep_multiplier_seconds = 0.01
    processes = [
        multiprocessing.Process(
            target=test_resolve,
            args=('%d.example.com' % i, sleep_multiplier_seconds * i))
        for i in range(num_requests)]
    total_timer = IntervalTimer()
    total_timer.start()
    with TestDnsProxyServer(self.interval_timer):
      with TestTrafficShaper(
          self.interval_timer,
          delay_ms='100'):
        for p in processes:
          p.start()
        for p in processes:
          p.join()
    total_timer.interval("total_time")
    logging.warn('%s', total_timer)
    # TODO(slamm): assert that the times are within certain values.


  def testHttpFetch(self):
    num_bytes = 1024 * 1024
    with TestWebProxyServer(self.interval_timer, num_bytes):
      with TestTrafficShaper(
          self.interval_timer,
          up_bandwidth='400KBit/s',
          down_bandwidth='2000KBit/s',
          delay_ms='100',
          init_cwnd='2'):
        data = urllib.urlopen(TEST_URL).read()
    self.assertEqual('\x00' * num_bytes, data)
    # TODO(slamm): assert that the times are within certain values.


if __name__ == '__main__':
  log_level = getattr(logging, 'DEBUG')
  logging.basicConfig(level=log_level,
                      format='%(asctime)s %(levelname)s %(message)s')
  unittest.main()

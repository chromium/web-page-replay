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
import logging
import sys
import time
import unittest

import third_party
import dns.resolver

import trafficshaper

TEST_DNS_HOST = '127.0.0.1'
TEST_DNS_NAMESERVER = '127.0.0.1'
TEST_DNS_PORT = 5555

# from timeit.py
if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time


class TestDnsProxyServer(dnsproxy.DnsProxyServer):

  def __init__(self):
    is_forward = False
    dnsproxy.DnsProxyServer.__init__(self,
        forward=False,
        private_passthrough=False,
        host=TEST_DNS_HOST,
        port=TEST_DNS_PORT)

  # TODO(slamm): Record when request received.


class TestResolver(object):
  def __init__(self):
    self.resolver = dns.resolver.get_default_resolver()

  def __call__(self):
    self.resolver.nameservers = [TEST_DNS_NAMESERVER]
    self.resolver.port = TEST_DNS_PORT
    hostname = 'example.com'
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


class TrafficShaperTest(unittest.TestCase):
  def setUp(self):
    self.timer = default_timer
    self.resolver = TestResolver()
    self.orig_reply = dnsproxy.UdpDnsHandler.reply
    def instrumented_reply(handler, buf):
      self.reply_time = self.timer()
      self.orig_reply(handler, buf)
    dnsproxy.UdpDnsHandler.reply = instrumented_reply

  def tearDown(self):
    dnsproxy.UdpDnsHandler.reply = self.orig_reply

  def testResolve(self):
    with TestDnsProxyServer():
      with trafficshaper.TrafficShaper(
          host=TEST_DNS_HOST, dns_port=str(TEST_DNS_PORT), delay_ms='1000'):
        start_time = self.timer()
        ip = self.resolver()
        end_time = self.timer()
        self.assertEqual(TEST_DNS_NAMESERVER, ip)
        out_time = self.reply_time - start_time
        in_time = end_time - self.reply_time
        logging.warn('Times %s %s', out_time, in_time)

# Add traffic shapping.

if __name__ == '__main__':
  log_level = getattr(logging, 'INFO')
  logging.basicConfig(level=log_level,
                      format='%(asctime)s %(levelname)s %(message)s')
  unittest.main()

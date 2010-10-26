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

import errno
import logging
import platformsettings
import socket
import SocketServer

import third_party
import dns.resolver
import ipaddr

class DnsProxyError(Exception):
  pass

class PermissionDenied(DnsProxyError):
  pass


class RealDnsLookup(object):
  def __init__(self, name_servers=None):
    self.resolver = dns.resolver.get_default_resolver()
    self.resolver.nameservers = name_servers or ['8.8.8.8']
    self._cache = {}

  def __call__(self, hostname):
    try:
      ip = self._cache.get(hostname);
      if ip:
        logging.debug('_real_dns_lookup(%s) cache hit! -> %s', hostname, ip)
        return ip

      answers = self.resolver.query(hostname, 'A')
    except dns.resolver.NoAnswer:
      # TODO: should these exceptions be handled at the next level up?
      logging.debug('_real_dns_lookup(%s) -> None (NoAnswer)', hostname)
      return None
    except dns.resolver.NXDOMAIN:
      # TODO: should these exceptions be handled at the next level up?
      logging.debug('_real_dns_lookup(%s) -> None (NXDOMAIN)', hostname)
      return None
    ip = None
    if answers:
      ip = str(answers[0])
    logging.debug('_real_dns_lookup(%s) -> %s', hostname, ip)
    self._cache[hostname] = ip
    return ip


class UdpDnsHandler(SocketServer.DatagramRequestHandler):
  """Resolve DNS queries to localhost.

  Possible alternative implementation:
  http://howl.play-bow.org/pipermail/dnspython-users/2010-February/000119.html
  """

  STANDARD_QUERY_OPERATION_CODE = 0

  def handle(self):
    self.data = self.rfile.read()
    self.transaction_id = self.data[0]
    self.flags = self.data[1]
    self.qa_counts = self.data[4:6]
    self.domain = ''
    operation_code = (ord(self.data[2]) >> 3) & 15
    if operation_code == self.STANDARD_QUERY_OPERATION_CODE:
      self.wire_domain = self.data[12:]
      self.domain = self._domain(self.wire_domain)
    else:
      logging.debug("DNS request with non-zero operation code: %s",
                    operation_code)

    ip = self.server.host
    if self.server.is_private_passthrough:
      real_ip = self.server.real_dns_lookup(self.domain)
      if real_ip and ipaddr.IPv4Address(real_ip).is_private:
        ip = real_ip
    if ip == self.server.host:
      logging.debug('dnsproxy: handle(%s) -> %s', self.domain, self.server.host)
    else:
      logging.debug('dnsproxy: passthrough(%s) -> %s', self.domain, ip)
    self.reply(self.get_dns_reply(ip))

  @classmethod
  def _domain(cls, wire_domain):
    domain = ''
    index = 0
    length = ord(wire_domain[index])
    while length:
      domain += wire_domain[index + 1:index + length + 1] + '.'
      index += length + 1
      length = ord(wire_domain[index])
    return domain

  def reply(self, buf):
    self.wfile.write(buf)

  def get_dns_reply(self, ip):
    packet = ''
    if self.domain:
      packet = (
          self.transaction_id +
          self.flags +
          '\x81\x80' +        # standard query response, no error
          self.qa_counts * 2 + '\x00\x00\x00\x00' +  # Q&A counts
          self.wire_domain +
          '\xc0\x0c'          # pointer to domain name
          '\x00\x01'          # resource record type ("A" host address)
          '\x00\x01'          # class of the data
          '\x00\x00\x00\x3c'  # ttl (seconds)
          '\x00\x04' +        # resource data length (4 bytes for ip)
          socket.inet_aton(ip)
          )
    return packet


class DnsProxyServer(SocketServer.ThreadingUDPServer):
  def __init__(self, host='127.0.0.1', port=53, platform_settings=None,
               is_private_passthrough=True):
    self.host = host
    if not platform_settings:
      platform_settings = platformsettings.get_platform_settings()
    self.is_private_passthrough = is_private_passthrough
    self.real_dns_lookup = RealDnsLookup(
        name_servers=[platform_settings.get_primary_dns()])
    self.restore_primary_dns = platform_settings.restore_primary_dns
    try:
      SocketServer.ThreadingUDPServer.__init__(
          self, (host, port), UdpDnsHandler)
    except socket.error, (error_number, msg):
      if error_number == errno.EACCES:
        raise PermissionDenied
      raise
    logging.info('Started DNS server on (%s:%s)...', host, port)
    platform_settings.set_primary_dns(host)

  def cleanup(self):
    self.restore_primary_dns()
    self.shutdown()
    logging.info('Shutdown DNS server')

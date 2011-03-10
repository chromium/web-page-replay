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

import daemonserver
import errno
import logging
import platformsettings
import socket
import SocketServer
import threading

import third_party
import dns.resolver
import ipaddr


class DnsProxyException(Exception):
  pass


class RealDnsLookup(object):
  def __init__(self, name_servers=None):
    self.resolver = dns.resolver.get_default_resolver()
    self.resolver.nameservers = [
        platformsettings.get_platform_settings().get_original_primary_dns()]
    self.dns_cache_lock = threading.Lock()
    self.dns_cache = {}

  def __call__(self, hostname):
    """Return real IP for a host.

    Args:
      host: a hostname ending with a period (e.g. "www.google.com.")
    Returns:
      the IP address as a string (e.g. "192.168.25.2")
    """
    self.dns_cache_lock.acquire()
    ip = self.dns_cache.get(hostname)
    self.dns_cache_lock.release()
    if ip:
      logging.debug('_real_dns_lookup(%s) cache hit! -> %s', hostname, ip)
      return ip
    try:
      answers = self.resolver.query(hostname, 'A')
    except (dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.Timeout) as ex:
      logging.debug('_real_dns_lookup(%s) -> None (%s)',
                    hostname, ex.__class__.__name__)
      return None
    if answers:
      ip = str(answers[0])
    logging.debug('_real_dns_lookup(%s) -> %s', hostname, ip)
    self.dns_cache_lock.acquire()
    self.dns_cache[hostname] = ip
    self.dns_cache_lock.release()
    return ip


class DnsPrivatePassthroughFilter:
  """Allow private hosts to resolve to their real IPs."""
  def __init__(self, real_dns_lookup, skip_passthrough_hosts=()):
    """Initialize DnsPrivatePassthroughFilter.

    Args:
      real_dns_lookup: a function that resolves a host to an IP.
      skip_passthrough_hosts: an iterable of hosts that skip
        the private determination (i.e. avoids a real dns lookup
        for them).
    """
    self.real_dns_lookup = real_dns_lookup
    self.skip_passthrough_hosts = set(
        host + '.' for host in skip_passthrough_hosts)

  def __call__(self, host):
    """Return real IP for host if private.

    Args:
      host: a hostname ending with a period (e.g. "www.google.com.")
    Returns:
      If private, the real IP address as a string (e.g. 192.168.25.2)
      Otherwise, None.
    """
    if host not in self.skip_passthrough_hosts:
      real_ip = self.real_dns_lookup(host)
      if real_ip and ipaddr.IPv4Address(real_ip).is_private:
        return real_ip
    return None


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
    real_ip = self.server.passthrough_filter(self.domain)
    if real_ip:
      message = 'passthrough'
      ip = real_ip
    else:
      message = 'handle'
      ip = self.server.server_address[0]
    logging.debug('dnsproxy: %s(%s) -> %s', message, self.domain, ip)
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


class DnsProxyServer(SocketServer.ThreadingUDPServer,
                     daemonserver.DaemonServer):
  def __init__(self, use_forwarding, passthrough_filter=None, host='', port=53):
    """Initialize DnsProxyServer.

    Args:
      use_forwarding: a boolean that if true, changes primary DNS to host.
      passthrough_filter: a function that resolves a host to its real IP,
        or None, if it should resolve to the dnsproxy's address.
      host: a host string (name or IP) to bind the dns proxy and to which
        DNS requests will be resolved.
      port: an integer port on which to bind the proxy.
    """
    self.use_forwarding = use_forwarding
    self.passthrough_filter = passthrough_filter or (lambda host: None)
    self.platform_settings = platformsettings.get_platform_settings()
    try:
      SocketServer.ThreadingUDPServer.__init__(
          self, (host, port), UdpDnsHandler)
    except socket.error, (error_number, msg):
      if error_number == errno.EACCES:
        raise DnsProxyException(
            'Unable to bind DNS server on (%s:%s)' % (host, port))
      raise
    logging.info('Started DNS server on %s...', self.server_address)
    if self.use_forwarding:
      self.platform_settings.set_primary_dns(host)

  def cleanup(self):
    if self.use_forwarding:
      self.platform_settings.restore_primary_dns()
    self.shutdown()
    logging.info('Shutdown DNS server')

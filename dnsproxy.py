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
import socket
import SocketServer
import threading

import third_party
import dns.flags
import dns.message
import dns.rcode
import dns.resolver
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import ipaddr


class DnsProxyException(Exception):
  pass


class RealDnsLookup(object):
  def __init__(self, name_servers):
    if '127.0.0.1' in name_servers:
      raise DnsProxyException(
          'Invalid nameserver: 127.0.0.1 (causes an infinte loop)')
    self.resolver = dns.resolver.get_default_resolver()
    self.resolver.nameservers = name_servers
    self.dns_cache_lock = threading.Lock()
    self.dns_cache = {}

  def __call__(self, hostname, rdtype=dns.rdatatype.A):
    """Return real IP for a host.

    Args:
      host: a hostname ending with a period (e.g. "www.google.com.")
      rdtype: the query type (1 for 'A', 28 for 'AAAA')
    Returns:
      the IP address as a string (e.g. "192.168.25.2")
    """
    self.dns_cache_lock.acquire()
    ip = self.dns_cache.get(hostname)
    self.dns_cache_lock.release()
    if ip:
      return ip
    try:
      answers = self.resolver.query(hostname, rdtype)
    except (dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.Timeout) as ex:
      logging.debug('_real_dns_lookup(%s) -> None (%s)',
                    hostname, ex.__class__.__name__)
      return None
    if answers:
      ip = str(answers[0])
    self.dns_cache_lock.acquire()
    self.dns_cache[hostname] = ip
    self.dns_cache_lock.release()
    return ip


class DnsPrivatePassthroughFilter:
  """Allow private hosts to resolve to their real IPs.

  This only supports IPv4 lookups.
  """
  def __init__(self, web_proxy_ip, real_dns_lookup, skip_passthrough_hosts=()):
    """Initialize DnsPrivatePassthroughFilter.

    Args:
      web_proxy_ip: the IP address returned by __call__ for non-private hosts.
      real_dns_lookup: a function that resolves a host to an IP.
      skip_passthrough_hosts: an iterable of hosts that skip
        the private determination (i.e. avoids a real dns lookup
        for them).
    """
    self.web_proxy_ip = web_proxy_ip
    self.real_dns_lookup = real_dns_lookup
    self.skip_passthrough_hosts = set(
        host + '.' for host in skip_passthrough_hosts)

  def __call__(self, host):
    """Return real IPv4 for host if private.

    Args:
      host: a hostname ending with a period (e.g. "www.google.com.")
    Returns:
      ip address as a string or None (if lookup fails)
    """
    ip = self.web_proxy_ip
    if host not in self.skip_passthrough_hosts:
      real_ip = self.real_dns_lookup(host)
      if real_ip:
        if ipaddr.IPAddress(real_ip).is_private:
          ip = real_ip
      else:
        ip = None
    return ip


class UdpDnsHandler(SocketServer.DatagramRequestHandler):
  """Resolve DNS queries to localhost.

  Possible alternative implementation:
  http://howl.play-bow.org/pipermail/dnspython-users/2010-February/000119.html
  """

  STANDARD_QUERY_OPERATION_CODE = 0
  TTL_SECONDS = 60

  def handle(self):
    """Handle a DNS query.

    IPv6 requests (with rdtype AAAA) receive mismatched IPv4 responses
    (with rdtype A). To properly support IPv6, the http proxy would
    need both types of addresses. By default, Windows XP does not
    support IPv6.
    """
    self.data = self.rfile.read()
    self.query_message = dns.message.from_wire(self.data)
    self.question = self.query_message.question[0]  # assume one question
    self.question.rdtype = dns.rdatatype.A  # force IPv4 (AAAA is for IPv6)
    self.domain = self.question.name
    ip = self.server.passthrough_filter(self.domain)
    logging.debug('dnsproxy: %s -> %s%s', self.domain, ip,
                  ip == self.server.server_address[0] and ' (web proxy)' or '')
    self.wfile.write(self.get_dns_response(ip))

  def get_dns_response(self, ip):
    response_message = dns.message.make_response(self.query_message)
    response_message.flags |= dns.flags.AA | dns.flags.RA
    if ip:
      response_message.answer.append(
          dns.rrset.from_text(self.domain, self.TTL_SECONDS, dns.rdataclass.IN,
                              self.question.rdtype, ip))
    else:
      response_message.set_rcode(dns.rcode.NXDOMAIN)  # name error
    return response_message.to_wire()


class DnsProxyServer(SocketServer.ThreadingUDPServer,
                     daemonserver.DaemonServer):
  def __init__(self, passthrough_filter=None, host='', port=53):
    """Initialize DnsProxyServer.

    Args:
      passthrough_filter: a function that resolves a host to its real IP,
        or None, if it should resolve to the dnsproxy's address.
      host: a host string (name or IP) to bind the dns proxy and to which
        DNS requests will be resolved.
      port: an integer port on which to bind the proxy.
    """
    try:
      SocketServer.ThreadingUDPServer.__init__(
          self, (host, port), UdpDnsHandler)
    except socket.error, (error_number, msg):
      if error_number == errno.EACCES:
        raise DnsProxyException(
            'Unable to bind DNS server on (%s:%s)' % (host, port))
      raise
    self.passthrough_filter = passthrough_filter or (
        lambda host: self.server_address)
    logging.info('Started DNS server on %s...', self.server_address)

  def cleanup(self):
    self.shutdown()
    logging.info('Shutdown DNS server')

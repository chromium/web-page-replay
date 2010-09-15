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

import socket
import SocketServer


class UdpDNSHandler(SocketServer.DatagramRequestHandler):
  def handle(self):
    self.reply_ip = '127.0.0.1'
    self.data = self.rfile.read()
    self.domain = ''
    type = (ord(self.data[2]) >> 3) & 15   # Opcode bits
    if type == 0:                     # Standard query
      ini = 12
      lon = ord(self.data[ini])
      while lon != 0:
        self.domain += self.data[ini+1:ini+lon+1] + '.'
        ini += lon + 1
        lon = ord(self.data[ini])

    self.reply(self.get_dns_reply(self.reply_ip))

  def reply(self, buf):
    self.wfile.write(buf)

  def get_dns_reply(self, ip):
    packet = ''
    if self.domain:
      packet += self.data[:2] + "\x81\x80"
      packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'      # Questions and Answers Counts
      packet += self.data[12:]                                            # Original Domain Name Question
      packet += '\xc0\x0c'                                                # Pointer to domain name
      packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'                # Response type, ttl and resource data length -> 4 bytes
      packet += str.join('' , map(lambda x: chr(int(x)), ip.split('.')))  # 4bytes of IP
    return packet

  def set_reply_ip(self, ip):
    self.reply_ip = ip


class DNSProxyServer(SocketServer.ThreadingUDPServer):
  def __init__(self, host='localhost', port=53):
    SocketServer.ThreadingUDPServer.__init__(self, (host, port), UdpDNSHandler)
    print 'Faking DNS on (%s:%s)...' % (host, port)


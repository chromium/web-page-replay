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

import logging
import platformsettings
import re


# Mac has broken bandwitdh parsing, so double check the values.
# On Mac OS X 10.6, "KBit/s" actually uses "KByte/s".
BANDWIDTH_PATTERN = r'0|\d+[KM]?(bit|Byte)/s'


class TrafficShaperException(Exception):
  pass


class BandwidthValueError(TrafficShaperException):
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return 'Value, "%s", does not match regex: %s' % (
        self.value, BANDWIDTH_PATTERN)


class TrafficShaper(object):

  _UPLOAD_PIPE = '1'     # Enforces overall upload bandwidth.
  _UPLOAD_QUEUE = '2'    # Shares upload bandwidth among source ports.
  _DOWNLOAD_PIPE = '3'   # Enforces overall download bandwidth.
  _DOWNLOAD_QUEUE = '4'  # Shares download bandwidth among destination ports.

  _BANDWIDTH_RE = re.compile(BANDWIDTH_PATTERN)

  """Manages network traffic shaping."""
  def __init__(self,
               dont_use=None,
               host='127.0.0.1',
               port='80',
               dns_port='53',
               up_bandwidth='0',
               down_bandwidth='0',
               delay_ms='0',
               packet_loss_rate='0',
               init_cwnd='0'):
    """Start shaping traffic.

    Args:
      host: a host string (name or IP) for the web proxy.
      port: a port string (e.g. '80') for the web proxy.
      dns_port: a port string for the dns proxy (for unit testing).
      up_bandwidth: Upload bandwidth
      down_bandwidth: Download bandwidth
           Bandwidths measured in [K|M]{bit/s|Byte/s}. '0' means unlimited.
      delay_ms: Propagation delay in milliseconds. '0' means no delay.
      packet_loss_rate: Packet loss rate in range [0..1]. '0' means no loss.
      init_cwnd: the initial cwnd setting. '0' means no change.
    """
    assert dont_use is None  # Force args to be named.
    self.platformsettings = platformsettings.get_platform_settings()
    self.host = host
    self.port = port
    self.dns_port = dns_port
    self.up_bandwidth = up_bandwidth
    self.down_bandwidth = down_bandwidth
    self.delay_ms = delay_ms
    self.packet_loss_rate = packet_loss_rate
    self.init_cwnd = init_cwnd
    if not self._BANDWIDTH_RE.match(self.up_bandwidth):
      raise BandwidthValueError(self.up_bandwidth)
    if not self._BANDWIDTH_RE.match(self.down_bandwidth):
      raise BandwidthValueError(self.down_bandwidth)


  def __enter__(self):
    self.platformsettings.configure_loopback()
    if self.init_cwnd != '0':
      if self.platformsettings.is_cwnd_available():
        self.original_cwnd = self.platformsettings.get_cwnd()
        self.platformsettings.set_cwnd(self.init_cwnd)
      else:
        logging.error('Platform does not support setting cwnd.')
    try:
      self.platformsettings.ipfw('-q', 'flush')
    except:
      pass
    if (self.up_bandwidth == '0' and self.down_bandwidth == '0' and
        self.delay_ms == '0' and self.packet_loss_rate == '0'):
      return
    if not self.dns_port and not self.port:
      raise TrafficShaperException('No ports on which to shape traffic.')

    ports = ','.join(str(p) for p in (self.port, self.dns_port) if p)
    queue_size = self.platformsettings.get_ipfw_queue_slots()
    half_delay_ms = int(self.delay_ms) / 2  # split over up/down links

    try:
      # Configure upload shaping.
      self.platformsettings.ipfw(
          'pipe', self._UPLOAD_PIPE,
          'config',
          'bw', self.up_bandwidth,
          'delay', half_delay_ms,
          )
      self.platformsettings.ipfw(
          'queue', self._UPLOAD_QUEUE,
          'config',
          'pipe', self._UPLOAD_PIPE,
          'plr', self.packet_loss_rate,
          'queue', queue_size,
          'mask', 'src-port', '0xffff',
          )
      self.platformsettings.ipfw(
          'add',
          'queue', self._UPLOAD_QUEUE,
          'ip',
          'from', 'any',
          'to', self.host,
          'out',
          'dst-port', ports,
          )

      # Configure download shaping.
      self.platformsettings.ipfw(
          'pipe', self._DOWNLOAD_PIPE,
          'config',
          'bw', self.down_bandwidth,
          'delay', half_delay_ms,
          )
      self.platformsettings.ipfw(
          'queue', self._DOWNLOAD_QUEUE,
          'config',
          'pipe', self._DOWNLOAD_PIPE,
          'plr', self.packet_loss_rate,
          'queue', queue_size,
          'mask', 'dst-port', '0xffff',
          )
      self.platformsettings.ipfw(
          'add',
          'queue', self._DOWNLOAD_QUEUE,
          'ip',
          'from', self.host,
          'to', 'any',
          'out',
          'src-port', ports,
          )
      logging.info('Started shaping traffic')
    except Exception, e:
      raise TrafficShaperException('Unable to shape traffic: %s' % e)

  def __exit__(self, unused_exc_type, unused_exc_val, unused_exc_tb):
    self.platformsettings.unconfigure_loopback()
    if (self.init_cwnd != '0' and
        self.platformsettings.is_cwnd_available()):
      self.platformsettings.set_cwnd(self.original_cwnd)
    try:
      self.platformsettings.ipfw('-q', 'flush')
      logging.info('Stopped shaping traffic')
    except Exception, e:
      raise TrafficShaperException('Unable to stop shaping traffic: %s' % e)

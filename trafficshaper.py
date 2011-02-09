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


class TrafficShaperException(Exception):
  pass


class TrafficShaper(object):

  _UPLOAD_PIPE = '1'     # Enforces overall upload bandwidth.
  _UPLOAD_QUEUE = '2'    # Shares upload bandwidth among sockets.
  _DOWNLOAD_PIPE = '3'   # Enforces overall download bandwidth.
  _DOWNLOAD_QUEUE = '4'  # Shares download bandwidth among sockets.
  _DNS_PIPE = '5'        # Enforces RTT for DNS requests.
  _RULE_SET = '6'        # Groups all pipes and queues.

  """Manages network traffic shaping."""
  def __init__(self,
               shape_dns,
               up_bandwidth = '0',
               down_bandwidth = '0',
               delay_ms = '0',
               packet_loss_rate = '0',
               init_cwnd = 0):
    """Start shaping traffic.

    Args:
      shape_dns: Iff true, delay_ms and packet_loss_rate will also apply to DNS
           traffic.
      up_bandwidth: Upload bandwidth
      down_bandwidth: Download bandwidth
           Bandwidths measured in [K|M]{bit/s|Byte/s}. '0' means unlimited.
      delay_ms: Propagation delay in milliseconds. '0' means no delay.
      packet_loss_rate: Packet loss rate in range [0..1]. '0' means no loss.
    """
    self.platformsettings = platformsettings.get_platform_settings()
    self.shape_dns = shape_dns
    self.up_bandwidth = up_bandwidth
    self.down_bandwidth = down_bandwidth
    self.delay_ms = delay_ms
    self.packet_loss_rate = packet_loss_rate
    self.init_cwnd = init_cwnd
    self.is_traffic_shaping = False

  def __enter__(self):
    if self.init_cwnd > 0:
      self.original_cwnd = self.platformsettings.get_cwnd()
      self.platformsettings.set_cwnd(self.init_cwnd)

    if self.is_traffic_shaping:
      self.platformsettings.ipfw(['delete', self._RULE_SET])
    if (self.up_bandwidth == '0' and self.down_bandwidth == '0' and
        self.delay_ms == '0' and self.packet_loss_rate == '0'):
      return

    queue_size = str(self.platformsettings.get_ipfw_queue_slots())

    # To distribute full delay across the uplink and downlink bandwidths evenly.
    half_delay_ms = str(int(int(self.delay_ms) / 2))

    try:
      # Configure DNS shaping.
      if self.shape_dns:
        self.platformsettings.ipfw([
            'pipe', self._DNS_PIPE,
            'config',
            'bw', '0',
            'delay', self.delay_ms,
            'plr', self.packet_loss_rate,
        ])
        self.platformsettings.ipfw([
            'add', self._RULE_SET,
            'pipe', self._DNS_PIPE,
            'udp',
            'from', '127.0.0.1',
            'to', '127.0.0.1',
            'out',
            'dst-port', '53',
        ])

      # Configure upload shaping.
      self.platformsettings.ipfw([
          'pipe', self._UPLOAD_PIPE,
          'config',
          'bw', self.up_bandwidth,
          'delay', half_delay_ms,
      ])
      self.platformsettings.ipfw([
          'queue', self._UPLOAD_QUEUE,
          'config',
          'pipe', self._UPLOAD_PIPE,
          'plr', self.packet_loss_rate,
          'queue', queue_size,
          'mask', 'src-port', '0xffff',
      ])
      self.platformsettings.ipfw([
          'add', self._RULE_SET,
          'queue', self._UPLOAD_QUEUE,
          'tcp',
          'from', '127.0.0.1',
          'to', '127.0.0.1',
          'out',
          'dst-port', '80',
      ])

      # Configure download shaping.
      self.platformsettings.ipfw([
          'pipe', self._DOWNLOAD_PIPE,
          'config',
          'bw', self.down_bandwidth,
          'delay', half_delay_ms,
      ])
      self.platformsettings.ipfw([
          'queue', self._DOWNLOAD_QUEUE,
          'config',
          'pipe', self._DOWNLOAD_PIPE,
          'plr', self.packet_loss_rate,
          'queue', queue_size,
          'mask', 'dst-port', '0xffff',
      ])
      self.platformsettings.ipfw([
          'add', self._RULE_SET,
          'queue', self._DOWNLOAD_QUEUE,
          'tcp',
          'from', '127.0.0.1',
          'to', '127.0.0.1',
          'out',
          'src-port', '80',
      ])

      logging.info('Started shaping traffic')
      self.is_traffic_shaping = True
    except Exception, e:
      raise TrafficShaperException('Unable to shape traffic: %s ' % e)

  def __exit__(self, unused_exc_type, unused_exc_val, unused_exc_tb):
    if self.init_cwnd > 0:
      self.platformsettings.set_cwnd(self.original_cwnd)

    if not self.is_traffic_shaping:
      return
    try:
      self.platformsettings.ipfw(['delete', self._RULE_SET])
      logging.info('Stopped shaping traffic')
    except Exception, e:
      raise TrafficShaperException('Unable to shape traffic: %s ' % e)


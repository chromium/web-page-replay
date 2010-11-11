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
  """Manages network traffic shaping."""
  def __init__(self,
               shape_dns,
               up_bandwidth = '0',
               down_bandwidth = '0',
               delay_ms = '0',
               packet_loss_rate = '0'):
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
    self.is_traffic_shaping = False
    self.pipe_set = '5'  # We configure our rules on IPFW set #5.

  def __enter__(self):
    if self.is_traffic_shaping:
      self.platformsettings.ipfw(['delete', self.pipe_set])
    if (self.up_bandwidth == '0' and self.down_bandwidth == '0' and
        self.delay_ms == '0' and self.packet_loss_rate == '0'):
      return
    try:
      upload_pipe = '1'      # The IPFW pipe for upload rules.
      download_pipe = '2'    # The IPFW pipe for download rules.
      dns_pipe = '3'         # The IPFW pipe for DNS.

      # Distribute the delay across the uplink and downlink bandwidths evenly.
      self.delay_ms = str(int(self.delay_ms) / 2)

      # Configure DNS shaping.
      if self.shape_dns:
        self.platformsettings.ipfw([
            'pipe', dns_pipe,
            'config',
            'bw', '0',
            'delay', self.delay_ms,
            'plr', self.packet_loss_rate
        ])
        self.platformsettings.ipfw([
            'add', self.pipe_set,
            'pipe', dns_pipe,
            'udp',
            'from', 'any',
            'to', '127.0.0.1',
            'dst-port', '53'
        ])

      # Configure upload shaping.
      self.platformsettings.ipfw([
          'pipe', upload_pipe,
          'config',
          'bw', self.up_bandwidth,
          'delay', self.delay_ms,
          'plr', self.packet_loss_rate,
          'queue', '4000000'
      ])
      self.platformsettings.ipfw([
          'add', self.pipe_set,
          'pipe', upload_pipe,
          'out',
          'dst-port', '80'
      ])

      # Configure download shaping.
      self.platformsettings.ipfw([
          'pipe', download_pipe,
          'config',
          'bw', self.down_bandwidth,
          'delay', self.delay_ms,
          'plr', self.packet_loss_rate,
          'queue', '4000000'
      ])
      self._ipfw([
          'add', self.pipe_set,
          'pipe', download_pipe,
          'in',
          'src-port', '80'
      ])

      logging.info('Started shaping traffic')
      self.is_traffic_shaping = True
    except Exception, e:
      raise TrafficShaperException('Unable to shape traffic: %s ' % e)

  def __exit__(self, unused_exc_type, unused_exc_val, unused_exc_tb):
    if not self.is_traffic_shaping:
      return
    try:
      # Delete pipe 
      self.platformsettings.ipfw(['delete', self.pipe_set])
      logging.info('Stopped shaping traffic')
    except Exception, e:
      raise TrafficShaperException('Unable to shape traffic: %s ' % e)


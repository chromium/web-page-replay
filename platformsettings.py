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
import platform
import subprocess


class PlatformSettingsError(Exception):
  """Module catch-all error."""
  pass


class DnsReadError(PlatformSettingsError):
  """Raised when unable to read DNS settings."""
  pass


class DnsUpdateError(PlatformSettingsError):
  """Raised when unable to update DNS settings."""
  pass


class TrafficShapingError(PlatformSettingsError):
  """Raised when unable to shape traffic."""
  pass


class PlatformSettings(object):
  def __init__(self):
    self.original_primary_dns = None
    self.is_traffic_shaping = False

  def set_traffic_shaping(self, bandwidth='0', delay_ms='0',
                          packet_loss_rate='0'):
    """Start shaping traffic.

    Args:
      bandwidth: Bandwidth in [K|M]{bit/s|Byte/s}. '0' means unlimited.
      delay_ms: Propagation delay in milliseconds. '0' means no delay.
      packet_loss_rate: Packet loss rate in range [0..1]. '0' means no loss.
    """
    if self.is_traffic_shaping:
      self.restore_traffic_shaping()
    if bandwidth == '0' and delay_ms == '0' and packet_loss_rate == '0':
      return
    try:
      # Create pipe '1' with requested shape.
      self._ipfw([
          'pipe', '1',
          'config',
          'bw', bandwidth,
          'delay', delay_ms,
          'plr', packet_loss_rate
      ])
      # Install pipe '1'.
      self._ipfw(['add', '1', 'pipe', '1', 'src-ip', '127.0.0.1'])
      logging.info('Started shaping traffic')
      self.is_traffic_shaping = True
    except:
      raise TrafficShapingError()

  def restore_traffic_shaping(self):
    if not self.is_traffic_shaping:
      return
    try:
      # Delete pipe '1' (which was created in set_traffic_shaping).
      self._ipfw(['delete', '1'])
      logging.info('Stopped shaping traffic')
    except:
      raise TrafficShapingError()

  def get_primary_dns(self):
    raise NotImplementedError()

  def set_primary_dns(self, dns):
    raise NotImplementedError()

  def restore_primary_dns(self):
    if not self.original_primary_dns:
      raise DnsUpdateError('Cannot restore because never set.')
    self.set_primary_dns(self.original_primary_dns)
    self.original_primary_dns = None

  def _ipfw(self, args):
    raise NotImplementedError()


class PosixPlatformSettings(PlatformSettings):
  def _ipfw(self, args):
    subprocess.check_call(['ipfw'] + args)


class OsxPlatformSettings(PosixPlatformSettings):
  def _scutil(self, cmd):
    scutil = subprocess.Popen(
        ['scutil'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return scutil.communicate(cmd)[0]

  def _get_dns_service_key(self):
    # <dictionary> {
    #   PrimaryInterface : en1
    #   PrimaryService : 8824452C-FED4-4C09-9256-40FB146739E0
    #   Router : 192.168.1.1
    # }
    output = self._scutil('show State:/Network/Global/IPv4')
    lines = output.split('\n')
    for line in lines:
      key_value = line.split(' : ')
      if key_value[0] == '  PrimaryService':
        return 'State:/Network/Service/%s/DNS' % key_value[1]
    raise DnsUpdateError('Did you run under sudo?')

  def get_primary_dns(self):
    # <dictionary> {
    #   ServerAddresses : <array> {
    #     0 : 198.35.23.2
    #     1 : 198.32.56.32
    #   }
    #   DomainName : apple.co.uk
    # }
    output = self._scutil('show %s' % self._get_dns_service_key())
    primary_line = output.split('\n')[2]
    line_parts = primary_line.split(' ')
    return line_parts[-1]

  def set_primary_dns(self, dns):
    if not self.original_primary_dns:
      self.original_primary_dns = self.get_primary_dns()
    command = '\n'.join([
      'd.init',
      'd.add ServerAddresses * %s' % dns,
      'set %s' % self._get_dns_service_key()
    ])
    self._scutil(command)
    logging.info('Changed system DNS to %s', dns)


class LinuxPlatformSettings(PosixPlatformSettings):
  """The following thread recommends a way to update DNS on Linux:

  http://ubuntuforums.org/showthread.php?t=337553

         sudo cp /etc/dhcp3/dhclient.conf /etc/dhcp3/dhclient.conf.bak
         sudo gedit /etc/dhcp3/dhclient.conf
         #prepend domain-name-servers 127.0.0.1;
         prepend domain-name-servers 208.67.222.222, 208.67.220.220;

         prepend domain-name-servers 208.67.222.222, 208.67.220.220;
         request subnet-mask, broadcast-address, time-offset, routers,
             domain-name, domain-name-servers, host-name,
             netbios-name-servers, netbios-scope;
         #require subnet-mask, domain-name-servers;

         sudo/etc/init.d/networking restart

  The code below does not try to change dchp and does not restart networking.
  Update this as needed to make it more robust on more systems.
  """
  RESOLV_CONF = '/etc/resolv.conf'

  def get_primary_dns(self):
    try:
      resolv_file = open(self.RESOLV_CONF)
    except IOError:
      raise DnsReadError()
    for line in resolv_file:
      if line.startswith('nameserver '):
        return line.split()[1]
    raise DnsReadError()

  def set_primary_dns(self, dns):
    """Replace the first nameserver entry with the one given.

    TODO: catch errors.
    """
    if not self.original_primary_dns:
      self.original_primary_dns = self.get_primary_dns()
    subprocess.Popen(
        ['perl', '-p', '-i.bak', '-e',
         'if (!$done) { s/^nameserver\s*(.*)/nameserver %s/; $done++ }' % dns,
         self.RESOLV_CONF]).communicate()
    if self.get_primary_dns() == dns:
      logging.info('Changed system DNS to %s', dns)
    else:
      raise DnsUpdateError('Did you run under sudo?')


class WindowsPlatformSettings(PlatformSettings):
  def _netsh_dns(self, cmd, arg=''):
    try:
      # TODO: "Local Area Connection" is a default, but not necessarily correct.
      subprocess.check_call(
          'netsh interface ip %s dns name="Local Area Connection" %s' % (
          cmd, arg))
    except subprocess.CalledProcessError, e:
      raise DnsUpdateError('Did you run as administrator?\n%s' % e)
   
  def get_primary_dns(self):
    self._netsh_dns('show')

  def set_primary_dns(self, dns):
    self._netsh_dns('set', 'static %s' % dns)

  def restore_primary_dns(self):
    self._netsh_dns('set', 'dhcp')


class WindowsXpPlatformSettings(WindowsPlatformSettings):
  def _ipfw(self, args):
    subprocess.check_call(['third_party\ipfw_win32\ipfw.exe'] + args)


def get_platform_settings():
  system = platform.system()
  release = platform.release()
  if system == 'Darwin':
    return OsxPlatformSettings()
  elif system == 'Linux':
    return LinuxPlatformSettings()
  elif system == 'Windows':
    if release == 'XP':
      return WindowsXpPlatformSettings()
    else:
      return WindowsPlatformSettings()
  raise NotImplementedError('Sorry, %s %s is not supported.', (system, release))

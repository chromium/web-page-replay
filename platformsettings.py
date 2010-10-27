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
import os
import platform
import re
import subprocess
import tempfile


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
    self.pipe_set = '5'         # We configure our rules on IPFW set #5.

  def set_traffic_shaping(self,
                          up_bandwidth = '0',
                          down_bandwidth = '0',
                          delay_ms = '0',
                          packet_loss_rate = '0'):
    """Start shaping traffic.

    Args:
      up_bandwidth: Upload bandwidth
      down_bandwidth: Download bandwidth
           Bandwidths measured in [K|M]{bit/s|Byte/s}. '0' means unlimited.
      delay_ms: Propagation delay in milliseconds. '0' means no delay.
      packet_loss_rate: Packet loss rate in range [0..1]. '0' means no loss.
    """
    if self.is_traffic_shaping:
      self.restore_traffic_shaping()
    if up_bandwidth == '0' and down_bandwidth == '0' and \
       delay_ms == '0' and packet_loss_rate == '0':
      return
    try:
      upload_pipe = '1'      # The IPFW pipe for upload rules.
      download_pipe = '2'    # The IPFW pipe for download rules.
      dns_pipe = '3'         # The IPFW pipe for DNS.

      # Distribute the delay across the uplink and downlink bandwidths evenly.
      delay_ms = str(int(delay_ms) / 2)

      # Configure DNS shaping.
      self._ipfw([
          'pipe', dns_pipe,
          'config',
          'bw', '0',
          'delay', delay_ms,
          'plr', packet_loss_rate
      ])
      self._ipfw(['add', self.pipe_set,
                  'pipe', dns_pipe,
                  'udp',
                  'from', 'any',
                  'to', '127.0.0.1',
                  'dst-port', '53'])

      # Configure upload shaping.
      self._ipfw([
          'pipe', upload_pipe,
          'config',
          'bw', up_bandwidth,
          'delay', delay_ms,
          'plr', packet_loss_rate,
          'queue', '4000000'
      ])
      self._ipfw(['add', self.pipe_set,
                  'pipe', upload_pipe,
                  'out',
                  'dst-port', '80'
      ])

      # Configure download shaping.
      self._ipfw([
          'pipe', download_pipe,
          'config',
          'bw', down_bandwidth,
          'delay', delay_ms,
          'plr', packet_loss_rate,
          'queue', '4000000'
      ])
      self._ipfw(['add', self.pipe_set,
                  'pipe', download_pipe,
                  'in',
                  'src-port', '80'
      ])

      logging.info('Started shaping traffic')
      self.is_traffic_shaping = True
    except Exception, e:
      logging.critical("Traffic Shaping Exception ", e)
      raise TrafficShapingError()

  def restore_traffic_shaping(self):
    if not self.is_traffic_shaping:
      return
    try:
      # Delete pipe 
      self._ipfw(['delete', self.pipe_set])
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
  def _netsh_set_dns(self, args):
    try:
      subprocess.check_call('netsh interface ip set dns %s' % args)
    except subprocess.CalledProcessError, e:
      raise DnsUpdateError('Did you run as administrator?\n%s' % e)

  def _netsh_show_dns(self):
    """Return DNS information:

    Example output:

    Configuration for interface "Local Area Connection 3"
    DNS servers configured through DHCP:  None
    Register with which suffix:           Primary only

    Configuration for interface "Wireless Network Connection 2"
    DNS servers configured through DHCP:  192.168.1.1
    Register with which suffix:           Primary only
    """
    return subprocess.Popen(
        ['netsh', 'interface', 'ip', 'show', 'dns'],
        stdout=subprocess.PIPE).communicate()[0]

  def _netsh_get_interface_names(self):
    return re.findall(r'"(.+?)"', self._netsh_show_dns())

  def get_primary_dns(self):
    match = re.search(r':\s+(\d+\.\d+\.\d+\.\d+)', self._netsh_show_dns())
    return match and match.group(1) or None

  def set_primary_dns(self, dns):
    vbs = """Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2")
Set colNetCards = objWMIService.ExecQuery("Select * From Win32_NetworkAdapterConfiguration Where IPEnabled = True")
For Each objNetCard in colNetCards
  arrDNSServers = Array("%s")
  objNetCard.SetDNSServerSearchOrder(arrDNSServers)
Next
""" % dns
    vbs_file = tempfile.NamedTemporaryFile(suffix='.vbs', delete=False)
    vbs_file.write(vbs)
    vbs_file.close()
    subprocess.check_call(['cscript', '//nologo', vbs_file.name])
    os.remove(vbs_file.name)

  def restore_primary_dns(self):
    for name in self._netsh_get_interface_names():
      logging.debug('Restoring DNS on "%s"' % name)
      self._netsh_set_dns('name="%s" dhcp primary' % name)


class WindowsXpPlatformSettings(WindowsPlatformSettings):
  def _ipfw(self, args):
    subprocess.check_call([r'third_party\ipfw_win32\ipfw.exe'] + args)


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

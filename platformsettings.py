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


import fileinput
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


class PlatformSettings(object):
  def __init__(self):
    self.original_primary_dns = None

  def get_primary_dns(self):
    raise NotImplementedError()

  def set_primary_dns(self, dns):
    if not self.original_primary_dns:
      self.original_primary_dns = self.get_primary_dns()
    self._set_primary_dns(dns)
    if self.get_primary_dns() == dns:
      logging.info('Changed system DNS to %s', dns)
    else:
      raise self._get_dns_update_error()

  def restore_primary_dns(self):
    if not self.original_primary_dns:
      raise DnsUpdateError('Cannot restore because never set.')
    self.set_primary_dns(self.original_primary_dns)
    self.original_primary_dns = None

  def ipfw(self, args):
    raise NotImplementedError()

  def is_cwnd_available(self):
    return False

  def set_cwnd(self, args):
    logging.error("Platform does not support setting cwnd.")

  def get_cwnd(self):
    logging.error("Platform does not support getting cwnd.")

  def get_ipfw_queue_slots(self):
    return 500

  def configure_loopback(self):
    """
    Configure loopback to be realistic.

    We use loopback for much of our testing, and on some systems, loopback
    behaves differently from real interfaces.
    """
    logging.error("Platform does not support loopback configuration.")
    pass

  def unconfigure_loopback(self):
    pass


class PosixPlatformSettings(PlatformSettings):
  def ipfw(self, args):
    subprocess.check_call(['ipfw'] + args)

  def _get_dns_update_error(self):
    return DnsUpdateError('Did you run under sudo?')


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
    raise self._get_dns_update_error()

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

  def _set_primary_dns(self, dns):
    command = '\n'.join([
      'd.init',
      'd.add ServerAddresses * %s' % dns,
      'set %s' % self._get_dns_service_key()
    ])
    self._scutil(command)

  def get_ipfw_queue_slots(self):
    return 100


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
  TCP_INIT_CWND = 'net/ipv4/tcp_init_cwnd'
  TCP_BASE_MSS = 'net/ipv4/tcp_base_mss'
  TCP_MTU_PROBING = 'net/ipv4/tcp_mtu_probing'

  def get_primary_dns(self):
    try:
      resolv_file = open(self.RESOLV_CONF)
    except IOError:
      raise DnsReadError()
    for line in resolv_file:
      if line.startswith('nameserver '):
        return line.split()[1]
    raise DnsReadError()

  def _set_primary_dns(self, dns):
    """Replace the first nameserver entry with the one given."""
    self._write_resolve_conf(dns)

  def _write_resolve_conf(self, dns):
    is_first_nameserver_replaced = False
    # The fileinput module uses sys.stdout as the edited file output.
    for line in fileinput.input(self.RESOLV_CONF, inplace=1, backup='.bak'):
      if line.startswith('nameserver ') and not is_first_nameserver_replaced:
        print 'nameserver %s' % dns
        is_first_nameserver_replaced = True
      else:
        print line,
    if not is_first_nameserver_replaced:
      raise DnsUpdateError('Could not find a suitable namserver entry in %s' %
                           self.RESOLV_CONF)

  def has_sysctl(self, name):
    filename = '/proc/sys/' + name
    return os.path.exists(filename)

  def set_sysctl(self, name, value):
    try:
      filename = '/proc/sys/' + name
      with open(filename, 'w+') as f:
        f.write(str(value))
    except IOError, e:
      logging.error("Unable to set sysctl %s: %s", name, e)

  def get_sysctl(self, name):
    try:
      filename = '/proc/sys/' + name
      with open(filename) as f:
        return int(f.read())
    except IOError, e:
      logging.error("Unable to get sysctl %s: %s", name, e)
      return None

  def is_cwnd_available(self):
    return self.has_sysctl(self.TCP_INIT_CWND)

  def set_cwnd(self, args):
    self.set_sysctl(self.TCP_INIT_CWND, str(args))

  def get_cwnd(self):
    return self.get_sysctl(self.TCP_INIT_CWND)

  def configure_loopback(self):
    """
    Linux will use jumbo frames by default (16KB), using the combination
    of MTU probing and a base MSS makes it use normal sized packets.

    The reason this works is because tcp_base_mss is only used when MTU
    probing is enabled.  And since we're using the max value, it will
    always use the reasonable size.  This is relevant for server-side realism.
    The client-side will vary depending on the client TCP stack config.
    """
    ENABLE_MTU_PROBING = 2
    TCP_FULL_MSS = 1460
    self.saved_tcp_mtu_probing = self.get_sysctl(self.TCP_MTU_PROBING)
    self.set_sysctl(self.TCP_MTU_PROBING, ENABLE_MTU_PROBING)
    self.saved_tcp_base_mss = self.get_sysctl(self.TCP_BASE_MSS)
    self.set_sysctl(self.TCP_BASE_MSS, TCP_FULL_MSS)

  def unconfigure_loopback(self):
    if self.saved_tcp_mtu_probing:
      self.set_sysctl(self.TCP_MTU_PROBING, self.saved_tcp_mtu_probing)
    if self.saved_tcp_base_mss:
      self.set_sysctl(self.TCP_BASE_MSS, self.saved_tcp_base_mss)

class WindowsPlatformSettings(PlatformSettings):
  def _get_dns_update_error(self):
    return DnsUpdateError('Did you run as administrator?')

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

  def _set_primary_dns(self, dns):
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


class WindowsXpPlatformSettings(WindowsPlatformSettings):
  def ipfw(self, args):
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
  raise NotImplementedError('Sorry %s %s is not supported.' % (system, release))

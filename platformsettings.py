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

# TODO: Rename the module and the classes here (e.g. dns_manager)

import logging
import platform
import subprocess
import third_party
import dns.resolver


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
  # TODO: Use different interface like:
  #     make_localhost_primary_dns and restore_primary_dns ?
  #     That would allow the code to be a little more careful about how it
  #     handles settings.

  def set_localhost_dns(self):
    """Configure DNS to use localhost.

    TODO: Should it be simply be put first in the list, or made the only option?
    """
    raise NotImplemented

  def restore_dns(self):
    """Restore the DNS configuration."""
    raise NotImplemented

  def get_default_nameservers(self):
    """Get the original list of DNS nameservers."""
    raise NotImplemented

  def get_primary_dns(self):
    raise NotImplemented

  def set_primary_dns(self, dns):
    raise NotImplemented

  def dns_lookup(self, hostname, dns_server='8.8.8.8'):
    # TODO: Check if this works on Mac OS X and Windows.
    # TODO: Use default nameservers (settings before using localhost).
    resolver = dns.resolver.get_default_resolver()
    resolver.nameservers = [dns_server]
    answers = resolver.query(hostname, 'A')
    ip = None
    if answers:
      ip = str(answers[0])
    logging.debug('dns_lookup(%s), answer: %s', hostname, ip)
    return ip


class OsxPlatformSettings(PlatformSettings):
  def _scutil(self, cmd):
    scutil = subprocess.Popen(
        ['scutil'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return scutil.communicate(cmd)[0]

  def _get_dns_service_key(self):
    # subKey [0] = State:/Network/Service/8824452C-FED4-4C09-9256-40FB146739E0/DNS
    # subKey [1] = State:/Network/Service/net.juniper.ncproxyd.main/DNS
    list_out = self._scutil('list State:/Network/Service/[^/]+/DNS')
    logging.debug('DNS service keys:\n%s', list_out)
    list_lines = list_out.split('\n')
    list_parts = list_lines[0].split(' ')
    service_keys = [line.split(' ')[-1] for line in list_lines if line]
    return service_keys[0]

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
    command = '\n'.join([
      'd.init',
      'd.add ServerAddresses * %s' % dns,
      'set %s' % self._get_dns_service_key()
    ])
    self._scutil(command)
    logging.info('Changed system DNS to %s', dns)

  def dns_lookup(self, hostname, dns_server='8.8.8.8'):
    resolver = dns.resolver.get_default_resolver()
    resolver.nameservers = [dns_server]
    answers = resolver.query(hostname, 'A')
    ip = None
    if answers:
      ip = str(answers[0])
    logging.debug('dns_lookup(%s), answer: %s', hostname, ip)
    return ip


class LinuxPlatformSettings(PlatformSettings):
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
      if line.startswith("nameserver "):
        return line.split()[1]
    raise DnsReadError()

  def set_primary_dns(self, dns):
    """Replace the first nameserver entry with the one given.

    TODO: save the old setting.
    TODO: catch errors.
    """
    if self.get_primary_dns() == dns:
        return
    subprocess.Popen(
        ['perl', '-p', '-i.bak', '-e',
         'if (!$done) { s/^nameserver\s*(.*)/nameserver %s/; $done++ }' % dns,
         self.RESOLV_CONF]).communicate()
    if self.get_primary_dns() == dns:
      logging.info('Changed system DNS to %s', dns)
    else:
      raise DnsUpdateError()


class WindowsPlatformSettings(PlatformSettings):

  # Using Netsh: http://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/netsh.mspx?mfr=true
  # Netsh commands for Interface IP: http://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/netsh_int_ip.mspx?mfr=true

  # c:\windows\system32\netsh.exe

  def get_primary_dns(self):
    # netsh interface ip show dns name="Local Area Connection"
    pass

  def set_primary_dns(self, dns):
    # netsh interface ip set dns name="Local Area Connection" static 127.0.0.1
    # netsh interface ip set dns name="Local Area Connection" dhcp
    pass

def get_platform_settings():
  if platform.system() == 'Darwin':
    return OsxPlatformSettings()
  elif platform.system() == 'Linux':
    return LinuxPlatformSettings()
  # TODO: Support Win
  #elif platform.system() == 'Windows':
  #  return LinuxPlatformSettings()
  logging.error('Sorry, %s is not yet supported', platform.system())
  raise NotImplemented

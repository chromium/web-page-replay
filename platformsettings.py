#!/usr/bin/env python

import platform
import subprocess


class PlatformSettings(object):
  def get_primary_dns(self):
    raise NotImplemented

  def set_primary_dns(self, dns):
    raise NotImplemented


class OSXPlatformSettings(PlatformSettings):
  def _scutil(self, cmd):
    scutil = subprocess.Popen(['scutil'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return scutil.communicate(cmd)[0]

  def _get_dns_service_key(self):
    # TODO: There may be multiple keys
    #   subKey [0] = State:/Network/Service/8824452C-FED4-4C09-9256-40FB146739E0/DNS
    list_out = self._scutil('list State:/Network/Service/[^/]+/DNS')
    list_parts = list_out.split(' ')
    return list_parts[len(list_parts)-1]

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
    return line_parts[len(line_parts)-1]

  def set_primary_dns(self, dns):
    command = '\n'.join([
      'd.init',
      'd.add ServerAddresses * %s' % dns,
      'set %s' % self._get_dns_service_key()
    ])
    self._scutil(command)


def get_platform_settings():
  if platform.system() == 'Darwin':
    return OSXPlatformSettings()
  # TODO: Support Win and Linux
  print 'Sorry, %s is not yet supported' % platform.system()
  raise NotImplemented

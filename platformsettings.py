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

"""Provides cross-platform utility fuctions.

Example:
  import platformsettings
  ip = platformsettings.get_server_ip_address()

Functions with "_temporary_" in their name automatically clean-up upon
termination (via the atexit module).

For the full list of functions, see the bottom of the file.
"""

import atexit
import fileinput
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time


class PlatformSettingsError(Exception):
  """Module catch-all error."""
  pass


class DnsReadError(PlatformSettingsError):
  """Raised when unable to read DNS settings."""
  pass


class DnsUpdateError(PlatformSettingsError):
  """Raised when unable to update DNS settings."""
  pass


class NotAdministratorError(PlatformSettingsError):
  """Raised when not running as administrator."""
  pass


class CalledProcessError(PlatformSettingsError):
    """Raised when a _check_output() process returns a non-zero exit status."""
    def __init__(self, returncode, cmd):
        self.returncode = returncode
        self.cmd = cmd

    def __str__(self):
        return 'Command "%s" returned non-zero exit status %d' % (
            ' '.join(self.cmd), self.returncode)


def _check_output(*args):
  """Run Popen(*args) and return its output as a byte string.

  Python 2.7 has subprocess.check_output. This is essentially the same
  except that, as a convenience, all the positional args are used as
  command arguments.

  Args:
    *args: sequence of program arguments
  Raises:
    CalledProcessError if the program returns non-zero exit status.
  Returns:
    output as a byte string.
  """
  command_args = [str(a) for a in args]
  logging.debug(' '.join(command_args))
  process = subprocess.Popen(command_args,
      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  output = process.communicate()[0]
  retcode = process.poll()
  if retcode:
    raise CalledProcessError(retcode, command_args)
  return output


class _BasePlatformSettings(object):

  def get_system_logging_handler(self):
    """Return a handler for the logging module (optional)."""
    return None

  def rerun_as_administrator(self):
    """If needed, rerun the program with administrative privileges.

    Raises NotAdministratorError if unable to rerun.
    """
    pass

  def timer(self):
    """Return the current time in seconds as a floating point number."""
    return time.time()

  def get_server_ip_address(self, is_server_mode=False):
    """Returns the IP address to use for dnsproxy and ipfw."""
    if is_server_mode:
      return socket.gethostbyname(socket.gethostname())
    return '127.0.0.1'

  def get_httpproxy_ip_address(self, is_server_mode=False):
    """Returns the IP address to use for httpproxy."""
    if is_server_mode:
      return '0.0.0.0'
    return '127.0.0.1'

  def _ipfw_cmd(self):
    raise NotImplementedError

  def ipfw(self, *args):
    ipfw_cmd = self._ipfw_cmd() + args
    return _check_output(*ipfw_cmd)

  def ping_rtt(self, hostname):
    """Pings the hostname by calling the OS system ping command.
    Also stores the result internally.

    Args:
      hostname: hostname of the server to be pinged
    Returns:
      round trip time to the server in seconds, or 0 if unable to calculate RTT
    """
    raise NotImplementedError

  def _get_cwnd(self):
    return None

  def _set_cwnd(self, args):
    pass

  def set_temporary_tcp_init_cwnd(self, cwnd):
    cwnd = int(cwnd)
    original_cwnd = self._get_cwnd()
    if original_cwnd is None:
      raise PlatformSettingsError('Unable to get current tcp init_cwnd.')
    if cwnd == original_cwnd:
      logging.info('TCP init_cwnd already set to target value: %s', cwnd)
    else:
      self._set_cwnd(cwnd)
      if self._get_cwnd() == cwnd:
        logging.info('Changed cwnd to %s', cwnd)
        atexit.register(self._set_cwnd, original_cwnd)
      else:
        logging.error('Unable to update cwnd to %s', cwnd)

  def setup_temporary_loopback_config(self):
    """Setup the loopback interface similar to real interface.

    We use loopback for much of our testing, and on some systems, loopback
    behaves differently from real interfaces.
    """
    logging.error('Platform does not support loopback configuration.')

  def _get_primary_nameserver(self):
    raise NotImplementedError

  def _set_primary_nameserver(self):
    raise NotImplementedError

  def get_original_primary_nameserver(self):
    if not hasattr(self, '_original_nameserver'):
      self._original_nameserver = self._get_primary_nameserver()
      logging.info('Saved original primary DNS nameserver: %s',
                   self._original_nameserver)
    return self._original_nameserver

  def set_temporary_primary_nameserver(self, nameserver):
    orig_nameserver = self.get_original_primary_nameserver()
    self._set_primary_nameserver(nameserver)
    if self._get_primary_nameserver() == nameserver:
      logging.info('Changed temporary primary nameserver to %s', nameserver)
      atexit.register(self._set_primary_nameserver, orig_nameserver)
    else:
      raise self._get_dns_update_error()


class _PosixPlatformSettings(_BasePlatformSettings):
  PING_PATTERN = r'rtt min/avg/max/mdev = \d+\.\d+/(\d+\.\d+)/\d+\.\d+/\d+\.\d+'
  PING_CMD = ('ping', '-c', '3', '-i', '0.2', '-W', '1')
  # For OsX Lion non-root:
  PING_RESTRICTED_CMD = ('ping', '-c', '1', '-i', '1', '-W', '1')
  SUDO_PATH = '/usr/bin/sudo'

  def rerun_as_administrator(self):
    """If needed, rerun the program with administrative privileges.

    Raises NotAdministratorError if unable to rerun.
    """
    if os.geteuid() != 0:
      logging.warn('Rerunning with sudo: %s', sys.argv)
      os.execv(self.SUDO_PATH, ['--'] + sys.argv)

  def _ipfw_cmd(self):
    for ipfw_path in ['/usr/local/sbin/ipfw', '/sbin/ipfw']:
      if os.path.exists(ipfw_path):
        ipfw_cmd = (self.SUDO_PATH, ipfw_path)
        self._ipfw_cmd = lambda: ipfw_cmd  # skip rechecking paths
        return ipfw_cmd
    raise PlatformSettingsError('ipfw not found.')

  def _ping(self, hostname):
    """Return ping output or None if ping fails.

    Initially pings 'localhost' to test for ping command that works.
    If the tests fails, subsequent calls will return None without calling ping.

    Args:
      hostname: host to ping
    Returns:
      ping stdout string, or None if ping unavailable
    Raises:
      CalledProcessError if ping returns non-zero exit
    """
    if not hasattr(self, 'ping_cmd'):
      test_host = 'localhost'
      for self.ping_cmd in (self.PING_CMD, self.PING_RESTRICTED_CMD):
        try:
          if self._ping(test_host):
            break
        except (CalledProcessError, OSError) as e:
          last_ping_error = e
      else:
        logging.critical('Ping configuration failed: %s', last_ping_error)
        self.ping_cmd = None
    if self.ping_cmd:
      cmd = list(self.ping_cmd) + [hostname]
      return self._check_output(*cmd)
    return None

  def ping_rtt(self, hostname):
    """Pings the hostname by calling the OS system ping command.

    Args:
      hostname: hostname of the server to be pinged
    Returns:
      round trip time to the server in milliseconds, or 0 if unavailable
    """
    rtt = 0
    output = None
    try:
      output = self._ping(hostname)
    except CalledProcessError as e:
      logging.critical('Ping failed: %s', e)
    if output:
      match = re.search(self.PING_PATTERN, output)
      if match:
        rtt = float(match.groups()[0])
      else:
        logging.warning('Unable to ping %s: %s', hostname, output)
    return rtt


  def _get_dns_update_error(self):
    return DnsUpdateError('Did you run under sudo?')

  @classmethod
  def _sysctl(cls, *args, **kwargs):
    sysctl_args = []
    if kwargs.get('use_sudo'):
      sysctl_args.append(cls.SUDO_PATH)
    sysctl_args.append('/usr/sbin/sysctl')
    if not os.path.exists(sysctl_args[-1]):
      sysctl_args[-1] = '/sbin/sysctl'
    sysctl_args.extend(str(a) for a in args)
    sysctl = subprocess.Popen(
        sysctl_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout = sysctl.communicate()[0]
    return sysctl.returncode, stdout

  def has_sysctl(self, name):
    if not hasattr(self, 'has_sysctl_cache'):
      self.has_sysctl_cache = {}
    if name not in self.has_sysctl_cache:
      self.has_sysctl_cache[name] = self._sysctl(name)[0] == 0
    return self.has_sysctl_cache[name]

  def set_sysctl(self, name, value):
    rv = self._sysctl('%s=%s' % (name, value), use_sudo=True)[0]
    if rv != 0:
      logging.error('Unable to set sysctl %s: %s', name, rv)

  def get_sysctl(self, name):
    rv, value = self._sysctl('-n', name)
    if rv == 0:
      return value
    else:
      logging.error('Unable to get sysctl %s: %s', name, rv)
      return None

  def _check_output(self, *args):
    """Allow tests to override this."""
    return _check_output(*args)


class _OsxPlatformSettings(_PosixPlatformSettings):
  LOCAL_SLOWSTART_MIB_NAME = 'net.inet.tcp.local_slowstart_flightsize'

  def _scutil(self, cmd):
    scutil = subprocess.Popen(
        ['/usr/sbin/scutil'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    return scutil.communicate(cmd)[0]

  def _ifconfig(self, *args):
    return _check_output(self.SUDO_PATH, '/sbin/ifconfig', *args)

  def set_sysctl(self, name, value):
    rv = self._sysctl('-w', '%s=%s' % (name, value), use_sudo=True)[0]
    if rv != 0:
      logging.error('Unable to set sysctl %s: %s', name, rv)

  def _get_cwnd(self):
    return int(self.get_sysctl(self.LOCAL_SLOWSTART_MIB_NAME))

  def _set_cwnd(self, size):
    self.set_sysctl(self.LOCAL_SLOWSTART_MIB_NAME, size)

  def _get_loopback_mtu(self):
    config = self._ifconfig('lo0')
    match = re.search(r'\smtu\s+(\d+)', config)
    return int(match.group(1)) if match else None

  def setup_temporary_loopback_config(self):
    """Configure loopback to temporarily use reasonably sized frames.

    OS X uses jumbo frames by default (16KB).
    """
    TARGET_LOOPBACK_MTU = 1500
    original_mtu = self._get_loopback_mtu()
    if original_mtu is None:
      logging.error('Unable to read loopback mtu. Setting left unchanged.')
      return
    if original_mtu == TARGET_LOOPBACK_MTU:
      logging.debug('Loopback MTU already has target value: %d', original_mtu)
    else:
      self._ifconfig('lo0', 'mtu', TARGET_LOOPBACK_MTU)
      if self._get_loopback_mtu() == TARGET_LOOPBACK_MTU:
        logging.debug('Set loopback MTU to %d (was %d)',
                      TARGET_LOOPBACK_MTU, original_mtu)
        atexit.register(self._ifconfig, 'lo0', 'mtu', original_mtu)
      else:
        logging.error('Unable to change loopback MTU from %d to %d',
                      original_mtu, TARGET_LOOPBACK_MTU)

  def _get_dns_service_key(self):
    output = self._scutil('show State:/Network/Global/IPv4')
    lines = output.split('\n')
    for line in lines:
      key_value = line.split(' : ')
      if key_value[0] == '  PrimaryService':
        return 'State:/Network/Service/%s/DNS' % key_value[1]
    raise DnsReadError('Unable to find DNS service key: %s', output)

  def _get_primary_nameserver(self):
    output = self._scutil('show %s' % self._get_dns_service_key())
    match = re.search(
        br'ServerAddresses\s+:\s+<array>\s+{\s+0\s+:\s+((\d{1,3}\.){3}\d{1,3})',
        output)
    if match:
      return match.group(1)
    else:
      raise DnsReadError('Unable to find primary DNS server: %s', output)

  def _set_primary_nameserver(self, dns):
    command = '\n'.join([
      'd.init',
      'd.add ServerAddresses * %s' % dns,
      'set %s' % self._get_dns_service_key()
    ])
    self._scutil(command)


class _LinuxPlatformSettings(_PosixPlatformSettings):
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

         sudo /etc/init.d/networking restart

  The code below does not try to change dchp and does not restart networking.
  Update this as needed to make it more robust on more systems.
  """
  RESOLV_CONF = '/etc/resolv.conf'
  ROUTE_RE = re.compile('initcwnd (\d+)')
  TCP_BASE_MSS = 'net.ipv4.tcp_base_mss'
  TCP_MTU_PROBING = 'net.ipv4.tcp_mtu_probing'

  def _get_default_route_line(self):
    stdout = self._check_output('ip', 'route')
    for line in stdout.split('\n'):
      if line.startswith('default'):
        return line
    return None

  def _set_cwnd(self, cwnd):
    default_line = self._get_default_route_line()
    self._check_output(
        'ip', 'route', 'change', default_line, 'initcwnd', str(cwnd))

  def _get_cwnd(self):
    default_line = self._get_default_route_line()
    m = self.ROUTE_RE.search(default_line)
    if m:
      return int(m.group(1))
    # If 'initcwnd' wasn't found, then 0 means it's the system default.
    return 0

  def setup_temporary_loopback_config(self):
    """Setup Linux to temporarily use reasonably sized frames.

    Linux uses jumbo frames by default (16KB), using the combination
    of MTU probing and a base MSS makes it use normal sized packets.

    The reason this works is because tcp_base_mss is only used when MTU
    probing is enabled.  And since we're using the max value, it will
    always use the reasonable size.  This is relevant for server-side realism.
    The client-side will vary depending on the client TCP stack config.
    """
    ENABLE_MTU_PROBING = 2
    original_probing = self.get_sysctl(self.TCP_MTU_PROBING)
    self.set_sysctl(self.TCP_MTU_PROBING, ENABLE_MTU_PROBING)
    atexit.register(self.set_sysctl, self.TCP_MTU_PROBING, original_probing)

    TCP_FULL_MSS = 1460
    original_mss = self.get_sysctl(self.TCP_BASE_MSS)
    self.set_sysctl(self.TCP_BASE_MSS, TCP_FULL_MSS)
    atexit.register(self.set_sysctl, self.TCP_BASE_MSS, original_mss)

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
      raise DnsUpdateError('Could not find a suitable nameserver entry in %s' %
                           self.RESOLV_CONF)

  def _get_primary_nameserver(self):
    try:
      resolv_file = open(self.RESOLV_CONF)
    except IOError:
      raise DnsReadError()
    for line in resolv_file:
      if line.startswith('nameserver '):
        return line.split()[1]
    raise DnsReadError()

  def _set_primary_nameserver(self, dns):
    """Replace the first nameserver entry with the one given."""
    try:
      self._write_resolve_conf(dns)
    except OSError, e:
      if 'Permission denied' in e:
        raise self._get_dns_update_error()
      raise


class _WindowsPlatformSettings(_BasePlatformSettings):

  def get_system_logging_handler(self):
    """Return a handler for the logging module (optional).

    For Windows, output can be viewed with DebugView.
    http://technet.microsoft.com/en-us/sysinternals/bb896647.aspx
    """
    import ctypes
    output_debug_string = ctypes.windll.kernel32.OutputDebugStringA
    output_debug_string.argtypes = [ctypes.c_char_p]
    class DebugViewHandler(logging.Handler):
      def emit(self, record):
        output_debug_string('[wpr] ' + self.format(record))
    return DebugViewHandler()

  def rerun_as_administrator(self):
    """If needed, rerun the program with administrative privileges.

    Raises NotAdministratorError if unable to rerun.
    """
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
      raise NotAdministratorError('Rerun with administrator privileges.')
      #os.execv('runas', sys.argv)  # TODO: replace needed Windows magic

  def timer(self):
    """Return the current time in seconds as a floating point number.

    From time module documentation:
       On Windows, this function [time.clock()] returns wall-clock
       seconds elapsed since the first call to this function, as a
       floating point number, based on the Win32 function
       QueryPerformanceCounter(). The resolution is typically better
       than one microsecond.
    """
    return time.clock()

  def _arp(self, *args):
    return _check_output('arp', *args)

  def _route(self, *args):
    return _check_output('route', *args)

  def _ipconfig(self, *args):
    return _check_output('ipconfig', *args)

  def _get_mac_address(self, ip):
    """Return the MAC address for the given ip."""
    ip_re = re.compile(r'^\s*IP(?:v4)? Address[ .]+:\s+([0-9.]+)')
    for line in self._ipconfig('/all').splitlines():
      if line[:1].isalnum():
        current_ip = None
        current_mac = None
      elif ':' in line:
        line = line.strip()
        ip_match = ip_re.match(line)
        if ip_match:
          current_ip = ip_match.group(1)
        elif line.startswith('Physical Address'):
          current_mac = line.split(':', 1)[1].lstrip()
        if current_ip == ip and current_mac:
          return current_mac
    return None

  def setup_temporary_loopback_config(self):
    """On Windows, temporarily route the server ip to itself."""
    ip = self.get_server_ip_address()
    mac_address = self._get_mac_address(ip)
    if self.mac_address:
      self._arp('-s', ip, self.mac_address)
      self._route('add', ip, ip, 'mask', '255.255.255.255')
      atexit.register(self._arp, '-d', ip)
      atexit.register(self._route, 'delete', ip, ip, 'mask', '255.255.255.255')
    else:
      logging.warn('Unable to configure loopback: MAC address not found.')
    # TODO(slamm): Configure cwnd, MTU size

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
    return _check_output('netsh', 'interface', 'ip', 'show', 'dns')

  def _get_primary_nameserver(self):
    match = re.search(r':\s+(\d+\.\d+\.\d+\.\d+)', self._netsh_show_dns())
    return match.group(1) if match else None

  def _set_primary_nameserver(self, dns):
    vbs = """
Set objWMIService = GetObject( _
   "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2")
Set colNetCards = objWMIService.ExecQuery( _
    "Select * From Win32_NetworkAdapterConfiguration Where IPEnabled = True")
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


class _WindowsXpPlatformSettings(_WindowsPlatformSettings):
  def _ipfw_cmd(self):
    return (r'third_party\ipfw_win32\ipfw.exe',)


def _new_platform_settings(system, release):
  """Make a new instance of PlatformSettings for the current system."""
  if system == 'Darwin':
    return _OsxPlatformSettings()
  if system == 'Linux':
    return _LinuxPlatformSettings()
  if system == 'Windows' and release == 'XP':
    return _WindowsXpPlatformSettings()
  if system == 'Windows':
    return _WindowsPlatformSettings()
  raise NotImplementedError('Sorry %s %s is not supported.' % (system, release))


# Create one instance of the platform-specific settings and
# make the functions available at the module-level.
_inst = _new_platform_settings(platform.system(), platform.release())

get_system_logging_handler = _inst.get_system_logging_handler
rerun_as_administrator = _inst.rerun_as_administrator
timer = _inst.timer

get_server_ip_address = _inst.get_server_ip_address
get_httpproxy_ip_address = _inst.get_httpproxy_ip_address
ipfw = _inst.ipfw
ping_rtt = _inst.ping_rtt
set_temporary_tcp_init_cwnd = _inst.set_temporary_tcp_init_cwnd
setup_temporary_loopback_config = _inst.setup_temporary_loopback_config

get_original_primary_nameserver = _inst.get_original_primary_nameserver
set_temporary_primary_nameserver = _inst.set_temporary_primary_nameserver

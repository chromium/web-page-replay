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

"""Replays web pages under simulated network conditions.

Must be run as administrator (sudo).

To record web pages:
  1. Start the program in record mode.
     $ sudo ./replay.py --record archive.wpr
  2. Load the web pages you want to record in a web browser. It is important to
     clear browser caches before this so that all subresources are requested
     from the network.
  3. Kill the process to stop recording.

To replay web pages:
  1. Start the program in replay mode with a previously recorded archive.
     $ sudo ./replay.py archive.wpr
  2. Load recorded pages in a web browser. A 404 will be served for any pages or
     resources not in the recorded archive.

Network simulation examples:
  # 128KByte/s uplink bandwidth, 4Mbps/s downlink bandwidth with 100ms RTT time
  $ sudo ./replay.py --up 128KByte/s --down 4Mbit/s --delay_ms=100 archive.wpr

  # 1% packet loss rate
  $ sudo ./replay.py --packet_loss_rate=0.01 archive.wpr
"""

import logging
import optparse
import socket
import sys
import time
import traceback

import customhandlers
import dnsproxy
import httparchive
import httpclient
import httpproxy
import platformsettings
import replayspdyserver
import trafficshaper


if sys.version < '2.6':
  print 'Need Python 2.6 or greater.'
  sys.exit(1)


def resolve_dns_to_remote_replay_server(platform_settings, dnsproxy_ip):
  """Set the primary dns nameserver to the replay dnsproxy.

  Restore the original primary dns nameserver on exit.

  Args:
    platform_settings: an instance of platformsettings.PlatformSettings
    dnsproxy_ip: the ip address to use as the primary dns server.
  """
  try:
    platform_settings.set_primary_dns(dnsproxy_ip)
    while True:
      time.sleep(1)
  except KeyboardInterrupt:
    logging.info('Shutting down.')
  finally:
    platform_settings.restore_primary_dns()


def main(options, replay_filename):
  exit_status = 0
  platform_settings = platformsettings.get_platform_settings()
  if options.server:
    resolve_dns_to_remote_replay_server(platform_settings, options.server)
    return exit_status
  host = platform_settings.get_server_ip_address(options.server_mode)

  web_server_class = httpproxy.HttpProxyServer
  web_server_kwargs = {
      'host': host,
      'port': options.port,
      }
  if options.spdy:
    assert not options.record, 'spdy cannot be used with --record.'
    web_server_class = replayspdyserver.ReplaySpdyServer
    web_server_kwargs['use_ssl'] = options.spdy != 'no-ssl'
    web_server_kwargs['certfile'] = options.certfile
    web_server_kwargs['keyfile'] = options.keyfile

  if options.record:
    http_archive = httparchive.HttpArchive()
    http_archive.AssertWritable(replay_filename)
  else:
    http_archive = httparchive.HttpArchive.Load(replay_filename)
    logging.info('Loaded %d responses from %s',
                 len(http_archive), replay_filename)

  custom_handlers = customhandlers.CustomHandlers(options.screenshot_dir)

  real_dns_lookup = dnsproxy.RealDnsLookup()
  if options.record:
    http_archive_fetch = httpclient.RecordHttpArchiveFetch(
        http_archive, real_dns_lookup, options.deterministic_script)
  else:
    http_archive_fetch = httpclient.ReplayHttpArchiveFetch(
        http_archive, options.diff_unknown_requests)

  dns_passthrough_filter = None
  if options.dns_private_passthrough:
    skip_passthrough_hosts = set(request.host for request in http_archive)
    dns_passthrough_filter = dnsproxy.DnsPrivatePassthroughFilter(
        real_dns_lookup, skip_passthrough_hosts)

  dns_class = dnsproxy.DummyDnsServer
  if options.dns_forwarding:
    dns_class = dnsproxy.DnsProxyServer

  try:
    with dns_class(options.dns_forwarding, dns_passthrough_filter, host):
      with web_server_class(http_archive_fetch, custom_handlers,
                            **web_server_kwargs):
        with trafficshaper.TrafficShaper(
            host=host,
            port=options.shaping_port,
            up_bandwidth=options.up,
            down_bandwidth=options.down,
            delay_ms=options.delay_ms,
            packet_loss_rate=options.packet_loss_rate,
            init_cwnd=options.init_cwnd):
          while True:
            time.sleep(1)
  except KeyboardInterrupt:
    logging.info('Shutting down.')
  except (dnsproxy.DnsProxyException,
          trafficshaper.TrafficShaperException) as e:
    logging.critical(e)
    exit_status = 1
  except:
    print traceback.format_exc()
    exit_status = 2
  if options.record:
    http_archive.Persist(replay_filename)
    logging.info('Saved %d responses to %s', len(http_archive), replay_filename)
  return exit_status


def configure_logging(log_level_name, log_file_name=None):
  """Configure logging level and format.

  Args:
    log_level_name: 'debug', 'info', 'warning', 'error', or 'critical'.
    log_file_name: a file name
  """
  if logging.root.handlers:
    logging.critical('A logging method (e.g. "logging.warn(...)")'
                     ' was called before logging was configured.')
  log_level = getattr(logging, log_level_name.upper())
  log_format = '%(asctime)s %(levelname)s %(message)s'
  logging.basicConfig(level=log_level, format=log_format)
  if log_file_name:
    fh = logging.FileHandler(log_file_name)
    fh.setLevel(log_level)
    fh.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(fh)


if __name__ == '__main__':
  class PlainHelpFormatter(optparse.IndentedHelpFormatter):
    def format_description(self, description):
      if description:
        return description + '\n'
      else:
        return ''
  option_parser = optparse.OptionParser(
      usage='%prog [options] replay_file',
      formatter=PlainHelpFormatter(),
      description=__doc__,
      epilog='http://code.google.com/p/web-page-replay/')

  option_parser.add_option('-s', '--spdy', default=False,
      action='store',
      type='string',
      help='Use spdy to replay relay_file.  --spdy="no-ssl" uses SPDY without SSL.')
  option_parser.add_option('-r', '--record', default=False,
      action='store_true',
      help='Download real responses and record them to replay_file')
  option_parser.add_option('-l', '--log_level', default='debug',
      action='store',
      type='choice',
      choices=('debug', 'info', 'warning', 'error', 'critical'),
      help='Minimum verbosity level to log')
  option_parser.add_option('-f', '--log_file', default=None,
      action='store',
      type='string',
      help='Log file to use in addition to writting logs to stderr.')

  network_group = optparse.OptionGroup(option_parser,
      'Network Simulation Options',
      'These options configure the network simulation in replay mode')
  network_group.add_option('-u', '--up', default='0',
      action='store',
      type='string',
      help='Upload Bandwidth in [K|M]{bit/s|Byte/s}. Zero means unlimited.')
  network_group.add_option('-d', '--down', default='0',
      action='store',
      type='string',
      help='Download Bandwidth in [K|M]{bit/s|Byte/s}. Zero means unlimited.')
  network_group.add_option('-m', '--delay_ms', default='0',
      action='store',
      type='string',
      help='Propagation delay (latency) in milliseconds. Zero means no delay.')
  network_group.add_option('-p', '--packet_loss_rate', default='0',
      action='store',
      type='string',
      help='Packet loss rate in range [0..1]. Zero means no loss.')
  network_group.add_option('-w', '--init_cwnd', default='0',
      action='store',
      type='string',
      help='Set initial cwnd (linux only, requires kernel patch)')
  option_parser.add_option_group(network_group)

  harness_group = optparse.OptionGroup(option_parser,
      'Replay Harness Options',
      'These advanced options configure various aspects of the replay harness')
  harness_group.add_option('-S', '--server', default=None,
      action='store',
      type='string',
      help='IP address of host running "replay.py --server_mode". '
           'This only changes the primary DNS nameserver to use the given IP.')
  harness_group.add_option('-M', '--server_mode', default=False,
      action='store_true',
      help='Run replay DNS & http proxies, and trafficshaping on --port '
           'without changing the primary DNS nameserver. '
           'Other hosts may connect to this using "replay.py --server" '
           'or by pointing their DNS to this server.')
  harness_group.add_option('-n', '--no-deterministic_script', default=True,
      action='store_false',
      dest='deterministic_script',
      help='During a record, do not inject JavaScript to make sources of '
           'entropy such as Date() and Math.random() deterministic. CAUTION: '
           'With this option many web pages will not replay properly.')
  harness_group.add_option('-D', '--diff_unknown_requests', default=False,
      action='store_true',
      dest='diff_unknown_requests',
      help='During replay, show a unified diff of any unknown requests against '
           'their nearest match in the archive.')
  harness_group.add_option('-I', '--screenshot_dir', default=None,
      action='store',
      type='string',
      help='Save PNG images of the loaded page in the given directory.')
  harness_group.add_option('-P', '--no-dns_private_passthrough', default=True,
      action='store_false',
      dest='dns_private_passthrough',
      help='Don\'t forward DNS requests that resolve to private network '
           'addresses. CAUTION: With this option important services like '
           'Kerberos will resolve to the HTTP proxy address.')
  harness_group.add_option('-x', '--no-dns_forwarding', default=True,
      action='store_false',
      dest='dns_forwarding',
      help='Don\'t forward DNS requests to the local replay server.'
           'CAUTION: With this option an external mechanism must be used to '
           'forward traffic to the replay server.')
  harness_group.add_option('-o', '--port', default=80,
      action='store',
      type='int',
      help='Port number to listen on.')
  harness_group.add_option('--shaping_port', default=0,
      action='store',
      type='int',
      help='Port to apply traffic shaping to.  \'0\' means use the same '
           'port as the listen port (--port)')
  harness_group.add_option('-c', '--certfile', default='',
      action='store',
      dest='certfile',
      type='string',
      help='Certificate file for use with SSL')
  harness_group.add_option('-k', '--keyfile', default='',
      action='store',
      dest='keyfile',
      type='string',
      help='Key file for use with SSL')
  option_parser.add_option_group(harness_group)

  options, args = option_parser.parse_args()

  configure_logging(options.log_level, options.log_file)

  if options.server:
    replay_filename = None
  elif len(args) != 1:
    option_parser.error('Must specify a replay_file')
  else:
    replay_filename = args[0]

  if options.record:
    if options.up != '0':
      option_parser.error('Option --up cannot be used with --record.')
    if options.down != '0':
      option_parser.error('Option --down cannot be used with --record.')
    if options.delay_ms != '0':
      option_parser.error('Option --delay_ms cannot be used with --record.')
    if options.packet_loss_rate != '0':
      option_parser.error(
          'Option --packet_loss_rate cannot be used with --record.')
    if options.spdy:
      option_parser.error('Option --spdy cannot be used with --record.')

  if options.server and options.server_mode:
    option_parser.error('Cannot run with both --server and --server_mode')

  if options.shaping_port == 0:
    options.shaping_port = options.port

  sys.exit(main(options, replay_filename))

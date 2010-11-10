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

description = """Replays web pages under simulated network conditions.

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
  $ sudo ./replay.py --packet_loss_rate=0.01 archive.wpr"""

import dnsproxy
import httpproxy
import logging
import optparse
import platformsettings
import socket
import sys
import threading
import time
import traceback


if sys.version < '2.6':
  print 'Need Python 2.6 or greater.'
  sys.exit(1)


def RunDNSServer():
  try:
    dns_server = dnsproxy.DnsProxyServer(
        is_private_passthrough=options.dns_private_passthrough)
    dns_thread = threading.Thread(target=dns_server.serve_forever)
    dns_thread.setDaemon(True)
    dns_thread.start()
    return dns_server
  except dnsproxy.PermissionDenied, e:
    logging.critical('Unable to bind to DNS port.\n%s' % e)
  except platformsettings.PlatformSettingsError, e:
    logging.critical('Unable to change primary DNS server.\n%s' % e)
  return None


def main(options, replay_file):
  platform_settings = platformsettings.get_platform_settings()

  dns_server = None
  if options.dns_forwarding:
    dns_server = RunDNSServer()

  try:
    # TODO: Because of python's Global Interpreter Lock (GIL), the threads
    # will run on the same CPU. Consider using processes instead because
    # the components do not need to communicate with each other. On Linux,
    # "taskset" could be used to assign each process to specific CPU/core.
    # Of course, only bother with this if the processing speed is an issue.
    # Some related discussion: http://stackoverflow.com/questions/990102/python-global-interpreter-lock-gil-workaround-on-multi-core-systems-using-tasks
    server = None
    if options.record:
      server = httpproxy.RecordHttpProxyServer(
          replay_file, options.deterministic_script, dns_server.real_dns_lookup)
    elif options.spdy:
      # TODO(lzheng): move this import to the front of the file once
      # nbhttp moves its logging config in server.py into main.
      import replayspdyserver
      server = replayspdyserver.ReplaySpdyServer(replay_file)
    else:
      server = httpproxy.ReplayHttpProxyServer(
          replay_file, options.deterministic_script)
    thread = threading.Thread(target=server.serve_forever)
    thread.setDaemon(True)
    thread.start()

    if not options.record:
      platform_settings.set_traffic_shaping(
          options.dns_forwarding,
          options.up, options.down, options.delay_ms, options.packet_loss_rate)

    start = time.time()
    while not options.time_limit or time.time() - start < options.time_limit:
      time.sleep(1)
  except IOError, (error_number, msg):
    logging.critical('Cannot open file: %s: %s', replay_file, msg)
  except platformsettings.TrafficShapingError:
    logging.critical('Unable to shape traffic.')
  except KeyboardInterrupt:
    pass
  except:
    print traceback.format_exc()
  finally:
    logging.info('Shutting down.')
    if dns_server:
      dns_server.cleanup()
    if server:
      server.cleanup()
    if not options.record:
      platform_settings.restore_traffic_shaping()


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
      description=description,
      epilog='http://code.google.com/p/web-page-replay/')

  option_parser.add_option('-s', '--spdy', default=False,
      action='store_true',
      help='Use spdy to replay relay_file.')
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
  option_parser.add_option('-t', '--time_limit', default=None,
      action='store',
      type='int',
      help='Maximum number of seconds to run before quiting.')

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
  option_parser.add_option_group(network_group)

  harness_group = optparse.OptionGroup(option_parser,
      'Replay Harness Options',
      'These advanced options configure various aspects of the replay harness')
  option_parser.add_option('-n', '--no-deterministic_script', default=True,
      action='store_false',
      dest='deterministic_script',
      help=('Don\'t inject JavaScript which makes sources of entropy such as '
            'Date() and Math.random() deterministic. CAUTION: With this option '
            'many web pages will not replay properly.'))
  option_parser.add_option('-P', '--no-dns_private_passthrough', default=True,
      action='store_false',
      dest='dns_private_passthrough',
      help='Don\'t forward DNS requests that resolve to private network '
           'addresses. CAUTION: With this option important services like '
           'Kerberos will resolve to the HTTP proxy address.')
  option_parser.add_option('-x', '--no-dns_forwarding', default=True,
      action='store_false',
      dest='dns_forwarding',
      help='Don\'t forward DNS requests to the local replay server.'
           'CAUTION: With this option an external mechanism must be used to '
           'forward traffic to the replay server.')
  option_parser.add_option_group(harness_group)

  options, args = option_parser.parse_args()

  log_level = logging.__dict__[options.log_level.upper()]
  logging.basicConfig(level=log_level,
                      format='%(asctime)s %(levelname)s %(message)s')

  if options.log_file:
    fh = logging.FileHandler(options.log_file)
    fh.setLevel(log_level)
    logging.getLogger('').addHandler(fh)

  if len(args) != 1:
    option_parser.error('Must specify a replay_file')

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

  if options.spdy and options.deterministic_script:
    logging.warning(
        'Option --deterministic-_script is ignored with --spdy.'
        'See http://code.google.com/p/web-page-replay/issues/detail?id=10')

  sys.exit(main(options, args[0]))

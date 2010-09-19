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

# TODO: Because of python's Global Interpreter Lock (GIL), the threads
# will run on the same CPU. Consider using processes instead because
# the components do not need to communicate with each other. On Linux,
# "taskset" could be used to assign each process to specific CPU/core.
# Of course, only bother with this if the processing speed is an issue.
# Some related discussion: http://stackoverflow.com/questions/990102/python-global-interpreter-lock-gil-workaround-on-multi-core-systems-using-tasks


import dnsproxy
import httpproxy
import logging
import optparse
import platformsettings
import socket
import sys
import threading
import time


def main(options, args):
  if not options.file:
    logging.critical('You must specify a --file to record to or reply from.')
    return

  platform_settings = platformsettings.get_platform_settings()

  try:
    dns_server = dnsproxy.DnsProxyServer(platform_settings=platform_settings)
  except dnsproxy.PermissionDenied:
    # TODO: fix comment for Windows.
    logging.critical('Unable to bind to DNS port. (Rerun with "sudo"?)')
    return
  except platformsettings.PlatformSettingsError:
    logging.critical('Unable to change primary DNS server.')
    return
  dns_thread = threading.Thread(target=dns_server.serve_forever)
  dns_thread.setDaemon(True)
  dns_thread.start()

  try:
    http_server = None
    http_server = httpproxy.HttpProxyServer(
        options.record, options.file, options.deterministic_script)
    http_thread = threading.Thread(target=http_server.serve_forever)
    http_thread.setDaemon(True)
    http_thread.start()

    if not options.record:
      platform_settings.set_traffic_shaping(
          options.bandwidth, options.delay_ms, options.packet_loss_rate)

    while 1:
      time.sleep(1)
  except IOError, (error_number, msg):
    logging.critical('Cannot open file: %s: %s', options.file, msg)
  except platformsettings.TrafficShapingError:
    logging.critical('Unable to shape traffic.')
  except:
    import traceback
    print traceback.format_exc()
    logging.info('Shutting down')
  finally:
    dns_server.cleanup()
    if http_server:
      http_server.cleanup()
    if not options.record:
      platform_settings.restore_traffic_shaping()


if __name__ == '__main__':
  option_parser = optparse.OptionParser()
  option_parser.add_option('-l', '--log_level', default='debug',
      help='Log level, one of {debug, info, warning, error, critical}')
  option_parser.add_option('-r', '--record', default=False, action='store_true',
      help='Whether to start in record mode.')
  option_parser.add_option('-f', '--file', default=None,
      help='Path to archive to record to or replay from.')
  option_parser.add_option('-b', '--bandwidth', default='0',
      help='Replay bandwidth in [K|M]{bit/s|Byte/s}. Zero means unlimited.')
  option_parser.add_option('-d', '--delay_ms', default='0',
      help='Replay propagation delay in milliseconds. Zero means no delay.')
  option_parser.add_option('-p', '--packet_loss_rate', default='0',
      help='Replay packet loss rate in range [0..1]. Zero means no loss.')
  option_parser.add_option('-s', '--deterministic_script', default=True,
      help=('Inject javascript which makes sources of entropy such as '
            'Date() and Math.random() deterministic.'))

  options, args = option_parser.parse_args()

  LEVELS = {'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL}
  logging.basicConfig(level=LEVELS.get(options.log_level, logging.NOTSET))

  sys.exit(main(options, args))

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

import cPickle
import dnsproxy
import httpproxy
import optparse
import platformsettings
import socket
import sys
import threading
import time


def main(options, args):
  if not options.file:
    print 'You must specify a --file to record to or reply from.'
    return

  try:
    replay_file = open(options.file, options.record and 'w' or 'r')
  except IOError, (error_number, msg):
    print 'Cannot open file: %s: %s' % (options.file, msg)
    return
  replay_archive = None
  if not options.record:
    replay_archive = cPickle.load(replay_file)
    replay_file.close()

  if options.test:
    dns_server = dnsproxy.DNSProxyServer(port=8353)
  else:
    try:
      dns_server = dnsproxy.DNSProxyServer()
    except dnsproxy.PermissionDenied:
      print 'Unable to bind to DNS port. Rerun with "sudo".'
      return
  dns_thread = threading.Thread(target=dns_server.serve_forever)
  dns_thread.setDaemon(True)
  dns_thread.start()

  platform_settings = platformsettings.get_platform_settings()
  original_dns = platform_settings.get_primary_dns()
  print "Original DNS:", original_dns
  platform_settings.set_primary_dns('127.0.0.1')

  # TODO: Start shaping traffic if recording.

  if options.test:
    http_server = httpproxy.HTTPProxyServer(replay_archive, port=8080)
  else:
    http_server = httpproxy.HTTPProxyServer(replay_archive)
  http_thread = threading.Thread(target=http_server.serve_forever)
  http_thread.setDaemon(True)
  http_thread.start()

  try:
    while 1:
      time.sleep(1)
  except:
    print 'Shutting down'
  finally:
    http_server.shutdown()
    # TODO: Stop shaping traffic if recording.
    platform_settings.set_primary_dns(original_dns)
    dns_server.shutdown()
    if options.record:
      cPickle.dump(http_server.http_archive, replay_file)
      replay_file.close()


if __name__ == '__main__':
  option_parser = optparse.OptionParser()
  option_parser.add_option('-r', '--record', default=False, action='store_true',
                           help='Whether to start in record mode.')
  option_parser.add_option('-f', '--file', default=None,
                           help='Path to archive to record to or replay from.')
  option_parser.add_option('-t', '--test', default=False, action='store_true',
                           help='Use test ports.')
  options, args = option_parser.parse_args()
  sys.exit(main(options, args))

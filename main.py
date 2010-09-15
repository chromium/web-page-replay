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
import os
import platformsettings
import sys
import threading
import time


def main(options, args):
  if not options.file:
    print 'You must specify a --file to record to or reply from.'
    return

  replay_archive = None
  if options.record:
    if not os.access(options.file, os.W_OK):
      print 'Cannot write %s' % options.file
      return
  else:
    if not os.access(options.file, os.R_OK):
      print 'Cannot read %s' % options.file
      return
    replay_archive = cPickle.load(open(options.file, 'r'))

  dns_server = dnsproxy.DNSProxyServer()
  dns_thread = threading.Thread(target=dns_server.serve_forever)
  dns_thread.setDaemon(True)
  dns_thread.start()
  
  platform_settings = platformsettings.get_platform_settings()
  original_dns = platform_settings.get_primary_dns()
  platform_settings.set_primary_dns('127.0.0.1')

  # TODO: Start shaping traffic if recording.

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
      dump_file = open(options.file, 'w')
      cPickle.dump(http_server.get_http_archive(), dump_file)
      dump_file.close()


if __name__ == '__main__':
  option_parser = optparse.OptionParser()
  option_parser.add_option('-r', '--record', default=False, action='store_true',
                           help='Whether to start in record mode.')
  option_parser.add_option('-f', '--file', default=None,
                           help='Path to archive to record to or replay from.')
  options, args = option_parser.parse_args()
  sys.exit(main(options, args))

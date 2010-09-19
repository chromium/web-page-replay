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

  try:
    replay_file = open(options.file, options.record and 'w' or 'r')
  except IOError, (error_number, msg):
    logging.critical('Cannot open file: %s: %s', options.file, msg)
    return
  replay_archive = None
  if not options.record:
    replay_archive = cPickle.load(replay_file)
    replay_file.close()
    logging.info('Loaded %d responses from %s', len(replay_archive), options.file)

  try:
    dns_server = dnsproxy.DnsProxyServer()
  except dnsproxy.PermissionDenied:
    # TODO: fix comment for Windows.
    logging.critical('Unable to bind to DNS port. (Rerun with "sudo"?)')
    return
  dns_thread = threading.Thread(target=dns_server.serve_forever)
  dns_thread.setDaemon(True)
  dns_thread.start()
  # TODO: Because of python's Global Interpreter Lock (GIL), the threads
  # will run on the same CPU. Consider using processes instead because
  # the components do not need to communicate with each other. On Linux,
  # "taskset" could be used to assign each process to specific CPU/core.
  # Of course, only bother with this if the processing speed is an issue.
  # Some related discussion: http://stackoverflow.com/questions/990102/python-global-interpreter-lock-gil-workaround-on-multi-core-systems-using-tasks
  platform_settings = platformsettings.get_platform_settings()
  try:
    platform_settings.set_primary_dns('127.0.0.1')
  except platformsettings.PlatformSettingsError:
    logging.critical('Unable to change primary DNS server.')
    return
  try:
    # TODO: Start shaping traffic if recording.

    http_server = None
    http_server = httpproxy.HttpProxyServer(replay_archive)
    http_thread = threading.Thread(target=http_server.serve_forever)
    http_thread.setDaemon(True)
    http_thread.start()

    while 1:
      time.sleep(1)
  except:
    import traceback
    print traceback.format_exc()
    logging.info('Shutting down')
  finally:
    platform_settings.restore_primary_dns()
    # TODO: Stop shaping traffic if recording.
    dns_server.shutdown()
    if http_server:
      http_server.shutdown()
      if options.record and http_server.http_archive:
        cPickle.dump(http_server.http_archive, replay_file)
        replay_file.close()


if __name__ == '__main__':
  option_parser = optparse.OptionParser()
  option_parser.add_option('-l', '--log_level', default='debug',
                           help='Log level, one of {debug, info, warning, error, critical}')
  option_parser.add_option('-r', '--record', default=False, action='store_true',
                           help='Whether to start in record mode.')
  option_parser.add_option('-f', '--file', default=None,
                           help='Path to archive to record to or replay from.')
  options, args = option_parser.parse_args()

  LEVELS = {'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL}
  logging.basicConfig(level=LEVELS.get(options.log_level, logging.NOTSET))

  sys.exit(main(options, args))

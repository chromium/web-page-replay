#!/usr/bin/env python

import dnsproxy
import httpproxy
import optparse
import platformsettings
import sys
import threading
import time


def main(options, args):
  dns_server = dnsproxy.DNSProxyServer()
  dns_thread = threading.Thread(target=dns_server.serve_forever)
  dns_thread.setDaemon(True)
  dns_thread.start()
  print 'Started DNS'
  
  platform_settings = platformsettings.get_platform_settings()
  original_dns = platform_settings.get_primary_dns()
  platform_settings.set_primary_dns('127.0.0.1')
  print 'Changed system DNS settings'

  # TODO: Start shaping traffic if recording.

  http_server = httpproxy.HTTPProxyServer(record=options.record, replay_file=options.file)
  http_thread = threading.Thread(target=http_server.serve_forever)
  http_thread.setDaemon(True)
  http_thread.start()
  print 'Started HTTP'

  if options.record:
    print 'Recording...'
  else:
    print 'Replaying...'

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


if __name__ == '__main__':
  option_parser = optparse.OptionParser()
  option_parser.add_option('-r', '--record', default=False, action='store_true',
                           help='Whether to start in record mode.')
  option_parser.add_option('-f', '--file', default=None,
                           help='Path to archive to record to or replay from.')
  options, args = option_parser.parse_args()
  sys.exit(main(options, args))

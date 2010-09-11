#!/usr/bin/env python

import dnsproxy
import getopt
import httpproxy
import platformsettings
import sys
import threading
import time


def main():
  try:
    # TODO: Accept a file to record to or replay from.
    opts, args = getopt.getopt(sys.argv[1:], 'r', ['record'])
  except getopt.GetoptError, err:
    print str(err)
    sys.exit(2)

  recording = False
  for o, a in opts:
    if o in ('-r', '--record'):
      recording = True

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

  http_server = httpproxy.HTTPProxyServer(record=recording)
  http_thread = threading.Thread(target=http_server.serve_forever)
  http_thread.setDaemon(True)
  http_thread.start()
  print 'Started HTTP'

  if recording:
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
  main()

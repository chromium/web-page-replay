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
import socket
import sys
import threading
import time
import traceback
import trafficshaper


if sys.version < '2.6':
  print 'Need Python 2.6 or greater.'
  sys.exit(1)


def main(options, replay_file):
  if options.record:
    replay_server_class = httpproxy.RecordHttpProxyServer
  elif options.spdy:
    # TODO(lzheng): move this import to the front of the file once
    # nbhttp moves its logging config in server.py into main.
    import replayspdyserver
    replay_server_class = replayspdyserver.ReplaySpdyServer
  else:
    replay_server_class = httpproxy.ReplayHttpProxyServer

  try:
    with dnsproxy.DnsProxyServer(options.dns_forwarding,
                                 options.dns_private_passthrough) as dns_server:
      with replay_server_class(replay_file,
                               options.deterministic_script,
                               dns_server.real_dns_lookup):
        with trafficshaper.TrafficShaper(options.dns_forwarding,
                                         options.up,
                                         options.down,
                                         options.delay_ms,
                                         options.packet_loss_rate):
          start = time.time()
          while (not options.time_limit or
                 time.time() - start < options.time_limit):
            time.sleep(1)
  except KeyboardInterrupt:
    logging.info('Shutting down.')
  except dnsproxy.DnsProxyException, e:
    logging.critical(e)
  except trafficshaper.TrafficShaperException, e:
    logging.critical(e)
  except:
    print traceback.format_exc()


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
  harness_group.add_option('-n', '--no-deterministic_script', default=True,
      action='store_false',
      dest='deterministic_script',
      help=('Don\'t inject JavaScript which makes sources of entropy such as '
            'Date() and Math.random() deterministic. CAUTION: With this option '
            'many web pages will not replay properly.'))
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
  option_parser.add_option_group(harness_group)

description = """
    This is a script for running automated network tests of chrome.
"""

import cookielib
import getpass
import logging
import optparse
import os
import subprocess
import sys
import tempfile
import time
import urllib
import urllib2
import runner_cfg

if sys.version < '2.6':
    print 'Need Python 2.6 or greater.'
    sys.exit(1)


# Some constants for our program

# The location of the Replay script
replay_path = "../replay.py"

# The name of the application we're using
benchmark_application_name = "perftracker"

# The location of the PerfTracker extension
perftracker_extension_path = "./extension"

# Function to login to the Google AppEngine app.
# This code credit to: http://dalelane.co.uk/blog/?p=303
def DoAppEngineLogin(username, password):
    target_authenticated_url = runner_cfg.benchmark_server_url

    # We use a cookie to authenticate with Google App Engine by registering a
    # cookie handler here, this will automatically store the cookie returned
    # when we use urllib2 to open http://<server>.appspot.com/_ah/login
    cookiejar = cookielib.LWPCookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar))
    urllib2.install_opener(opener)

    #
    # get an AuthToken from Google accounts
    #
    try:
        auth_uri = 'https://www.google.com/accounts/ClientLogin'
        authreq_data = urllib.urlencode({ "Email":   username,
                                          "Passwd":  password,
                                          "service": "ah",
                                          "source":  benchmark_application_name,
                                          "accountType": "HOSTED_OR_GOOGLE" })
        auth_req = urllib2.Request(auth_uri, data=authreq_data)
        auth_resp = urllib2.urlopen(auth_req)
        auth_resp_body = auth_resp.read()
        # The auth response includes several fields.  The part  we're
        # interested in is the bit after "Auth=".
        auth_resp_dict = dict(x.split("=")
                              for x in auth_resp_body.split("\n") if x)
        authtoken = auth_resp_dict["Auth"]

        # Get a cookie:
        # The call to request a cookie will also automatically redirect us to
        # the page that we want to go to. The cookie jar will automatically
        # provide the cookie when we reach the redirected location.
        serv_args = {}
        serv_args['continue'] = target_authenticated_url
        serv_args['auth']     = authtoken
        full_serv_uri = runner_cfg.benchmark_server_url + "_ah/login?%s" % (urllib.urlencode(serv_args))

        serv_req = urllib2.Request(full_serv_uri)
        serv_resp = urllib2.urlopen(serv_req)
        print "AppEngineLogin succeeded."
    except Exception, e: 
      logging.critical("DoAppEngineLogin failed: %s", e)
      return None
    return full_serv_uri

class TestInstance:
    def __init__(self, config, log_level):
        self.config = config
        self.log_level = log_level
        self.proxy_process = None

    def GenerateConfigFile(self, notes):
        # The PerfTracker extension requires this name in order to kick off.
        ext_suffix = "startbenchmark.html"
        self.filename = tempfile.mktemp(suffix=ext_suffix, prefix="")
        f = open(self.filename, "w+")
        def writeln(f, line):
          f.write(line + "\n")
        
        f.write("""
<body>
<textarea id=json></textarea>
<script>
var benchmark = {};
benchmark.user = "";  // XXXMB - fix me.
""")
        if not notes:
            notes = "";

        cmdline = "";    # TODO(mbelshe):  How to plumb this?

        writeln(f, "benchmark.notes = \"" + notes + "\";");
        writeln(f, "benchmark.cmdline = \"" + cmdline + "\";");
        writeln(f, "benchmark.server_url = \"" + runner_cfg.benchmark_server_url + "\";")
        writeln(f, "benchmark.server_login = \"" + options.login_url + "\";")
        writeln(f, "benchmark.iterations = " + str(self.config["iterations"]) + ";")
        writeln(f, "benchmark.download_bandwidth_kbps = " + str(self.config["download_bandwidth_kbps"]) + ";")
        writeln(f, "benchmark.upload_bandwidth_kbps = " + str(self.config["upload_bandwidth_kbps"]) + ";")
        writeln(f, "benchmark.round_trip_time_ms = " + str(self.config["round_trip_time_ms"]) + ";")
        writeln(f, "benchmark.packet_loss_rate = " + str(self.config["packet_loss_rate"]) + ";")
        if self.config["use_spdy"]:
            writeln(f, "benchmark.use_spdy = true;")
        else:
            writeln(f, "benchmark.use_spdy = false;")

        writeln(f, "benchmark.urls = [")
        for url in runner_cfg.configurations["urls"]:
            writeln(f, "  \"" + url + "\",")
 
        writeln(f, "];");
        f.write("""
var raw_json = JSON.stringify(benchmark);
document.getElementById("json").innerHTML = raw_json;
</script>
</body>
""")

        f.close()
        return

    def StartProxy(self):
        logging.debug("Starting Web-Page-Replay")
        log_level = "info"
        if self.log_level:
            log_level = self.log_level
        cmdline = [
          replay_path,
          "-x",  # Disables DNS intercepting
          "-d", str(self.config["download_bandwidth_kbps"]) + "KBit/s",
          "-u", str(self.config["upload_bandwidth_kbps"]) + "KBit/s",
          "-m", str(self.config["round_trip_time_ms"]),
          "-p", str(self.config["packet_loss_rate"]),
          "-l", log_level,
          runner_cfg.replay_data_archive
        ]
        logging.debug("Starting replay proxy: %s", str(cmdline))
        self.proxy_process = subprocess.Popen(cmdline)

        # We just changed the system resolv.conf.  If we go too fast here
	# it may still be pointing at the old version...  linux sux
        time.sleep(5)

    def StopProxy(self):
        if self.proxy_process:
            logging.debug("Stopping Web-Page-Replay")
            self.proxy_process.send_signal(2)  # SIGINT
            self.proxy_process.wait()

    def RunChrome(self, chrome_cmdline):
        start_file_url = "file://" + self.filename

        cmdline = [
            runner_cfg.chrome_path,
            "--host-resolver-rules=MAP * 127.0.0.1,EXCLUDE " + runner_cfg.benchmark_server, 
            "--disable-background-networking",
            "--enable-benchmarking",
            "--enable-logging",
            "--load-extension=" + perftracker_extension_path,
            "--log-level=0",
            "--no-first-run",
            "--no-js-randomization",
            "--user-data-dir=/tmp/foo",     # TODO(mbelshe) make dynamic
        ]
        if chrome_cmdline:
          cmdline.extend(chrome_cmdline.split(" "))
        cmdline.append(start_file_url)

        logging.debug("Starting chrome: %s", str(cmdline))
        chrome = subprocess.Popen(cmdline)
        chrome.wait();

    def RunTest(self, notes, chrome_cmdline):
        try:
            self.GenerateConfigFile(notes)
            self.StartProxy()
            self.RunChrome(chrome_cmdline)
        finally:
            logging.debug("Cleaning up test")
            self.StopProxy()
            self.Cleanup()

    def Cleanup(self):
        os.remove(self.filename)

def main(options):
    iterations = runner_cfg.configurations["iterations"]
    for plr in runner_cfg.configurations["packet_loss_rates"]:
        for network in runner_cfg.configurations["networks"]:
            for rtt in runner_cfg.configurations["round_trip_times"]:
                config = {
                    "iterations"             : iterations,
                    "download_bandwidth_kbps": network["download_bandwidth_kbps"],
                    "upload_bandwidth_kbps"  : network["upload_bandwidth_kbps"],
                    "round_trip_time_ms"     : rtt,
                    "packet_loss_rate"       : plr,
                    "use_spdy"               : False,
                }
                logging.debug("Running test configuration: %s", str(config))
                test = TestInstance(config, options.log_level)
                test.RunTest(options.notes, options.chrome_cmdline)

if __name__ == '__main__':
    log_levels = ('debug', 'info', 'warning', 'error', 'critical')

    class PlainHelpFormatter(optparse.IndentedHelpFormatter):
        def format_description(self, description):
            if description:
                return description + '\n'
            else:
                return ''

    option_parser = optparse.OptionParser(
            usage='%prog -u user',
            formatter=PlainHelpFormatter(),
            description=description,
            epilog='')

    option_parser.add_option('-l', '--log_level', default='info',
            action='store',
            type='choice',
            choices=log_levels,
            help='Minimum verbosity level to log')
    option_parser.add_option('-f', '--log_file', default=None,
            action='store',
            type='string',
            help='Log file to use in addition to writting logs to stderr.')
    option_parser.add_option('-c', '--chrome_cmdline', default=None,
            action='store',
            type='string',
            help='Command line options to pass to chrome.')
    option_parser.add_option('-n', '--notes', default=None,
            action='store',
            type='string',
            help='Notes to record with this test run.')
    option_parser.add_option('-u', '--user', default=None,
            action='store',
            type='string',
            help='Username for logging into appengine.')

    options, args = option_parser.parse_args()

    # Collect login credentials and verify
    if not options.user:
      option_parser.error('Must specify an appengine user for login')
    options.password = getpass.getpass(options.user + " password: ");
    options.login_url = DoAppEngineLogin(options.user, options.password)
    if not options.login_url:
      exit(-1)

    log_level = logging.__dict__[options.log_level.upper()]
    logging.basicConfig(level=log_level)
    if options.log_file:
        fh = logging.FileHandler(options.log_file)
        fh.setLevel(log_level)
        logging.getLogger('').addHandler(fh)

    sys.exit(main(options))

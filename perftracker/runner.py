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

description = """
    This is a script for running automated network tests of chrome.
"""

import cookielib
import getpass
import json
import logging
import optparse
import os
import platform
import signal
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
replay_path = '../replay.py'

# The name of the application we're using
benchmark_application_name = 'perftracker'

# The location of the PerfTracker extension
perftracker_extension_path = './extension'

# The server_port is the port which runs the webserver to test against.
server_port = 8000

# For SPDY testing, where we have both a frontend and backend server,
# this is the port to run the backend server.
backend_server_port = 8001

# Function to login to the Google AppEngine app.
# This code credit to: http://dalelane.co.uk/blog/?p=303
def DoAppEngineLogin(username, password):
  target_authenticated_url = runner_cfg.appengine_url

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
    authreq_data = urllib.urlencode({ 'Email':   username,
                                      'Passwd':  password,
                                      'service': 'ah',
                                      'source':  benchmark_application_name,
                                      'accountType': 'HOSTED_OR_GOOGLE' })
    auth_req = urllib2.Request(auth_uri, data=authreq_data)
    auth_resp = urllib2.urlopen(auth_req)
    auth_resp_body = auth_resp.read()
    # The auth response includes several fields.  The part  we're
    # interested in is the bit after 'Auth='.
    auth_resp_dict = dict(x.split('=') for x in auth_resp_body.split('\n') if x)
    authtoken = auth_resp_dict['Auth']

    # Get a cookie:
    # The call to request a cookie will also automatically redirect us to
    # the page that we want to go to. The cookie jar will automatically
    # provide the cookie when we reach the redirected location.
    serv_args = {}
    serv_args['continue'] = target_authenticated_url
    serv_args['auth']     = authtoken
    full_serv_uri = '%s_ah/login?%s' % (runner_cfg.appengine_url,
                                        urllib.urlencode(serv_args))

    serv_req = urllib2.Request(full_serv_uri)
    serv_resp = urllib2.urlopen(serv_req)
    print 'AppEngineLogin succeeded.'
  except Exception, e: 
    logging.critical('DoAppEngineLogin failed: %s', e)
    return None
  return full_serv_uri


# Clobber a tmp directory.  Be careful!
def ClobberTmpDirectory(tmpdir):
  # Do sanity checking so we don't clobber the wrong thing
  if len(tmpdir) == 0 or not tmpdir.startswith('/tmp/'):
    return

  try:
    for root, dirs, files in os.walk(tmpdir, topdown=False):
      for name in files:
        os.remove(os.path.join(root, name))
      for name in dirs:
        os.rmdir(os.path.join(root, name))
    os.rmdir(tmpdir)
  except:
    logging.error("Could not delete: " + tmpdir)
    pass

def _XvfbPidFilename(slave_build_name):
  """Returns the filename to the Xvfb pid file.  This name is unique for each
  builder. This is used by the linux builders."""
  return os.path.join(tempfile.gettempdir(),
                      'xvfb-' + slave_build_name  + '.pid')

def StartVirtualX(slave_build_name, build_dir):
  """Start a virtual X server and set the DISPLAY environment variable so sub
  processes will use the virtual X server.  Also start icewm. This only works
  on Linux and assumes that xvfb and icewm are installed.

  Args:
    slave_build_name: The name of the build that we use for the pid file.
        E.g., webkit-rel-linux.
    build_dir: The directory where binaries are produced.  If this is non-empty,
        we try running xdisplaycheck from |build_dir| to verify our X
        connection.
  """
  # We use a pid file to make sure we don't have any xvfb processes running
  # from a previous test run.
  StopVirtualX(slave_build_name)

  # Start a virtual X server that we run the tests in.  This makes it so we can
  # run the tests even if we didn't start the tests from an X session.
  proc = subprocess.Popen(['Xvfb', ':9', '-screen', '0', '1024x768x24', '-ac'],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  xvfb_pid_filename = _XvfbPidFilename(slave_build_name)
  open(xvfb_pid_filename, 'w').write(str(proc.pid))
  os.environ['DISPLAY'] = ':9'

  # Verify that Xvfb has started by using xdisplaycheck.
  if len(build_dir) > 0:
    xdisplaycheck_path = os.path.join(build_dir, 'xdisplaycheck')
    if os.path.exists(xdisplaycheck_path):
      print 'Verifying Xvfb has started...'
      status, output = commands.getstatusoutput(xdisplaycheck_path)
      if status != 0:
        print 'Xvfb return code (None if still running):', proc.poll()
        print 'Xvfb stdout and stderr:', proc.communicate()
        raise Exception(output)
      print '...OK'
  # Some ChromeOS tests need a window manager.
  subprocess.Popen('icewm', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def StopVirtualX(slave_build_name):
  """Try and stop the virtual X server if one was started with StartVirtualX.
  When the X server dies, it takes down the window manager with it.
  If a virtual x server is not running, this method does nothing."""
  xvfb_pid_filename = _XvfbPidFilename(slave_build_name)
  if os.path.exists(xvfb_pid_filename):
    # If the process doesn't exist, we raise an exception that we can ignore.
    try:
      os.kill(int(open(xvfb_pid_filename).read()), signal.SIGKILL)
    except OSError:
      pass
    os.remove(xvfb_pid_filename)


def _svn(cmd):
  """Returns output of given svn command."""
  svn = subprocess.Popen(
      ['svn', '--non-interactive', cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  return svn.communicate()[0]


def _get_value_for_key(lines, key):
  """Given list of |lines| with colon separated key value pairs, return the value of |key|."""
  for line in lines:
    parts = line.split(':')
    if parts[0].strip() == key:
      return parts[1].strip()
  return None


def GetCPU():
  # When /proc/cpuinfo exists it is more reliable than platform.
  if os.path.exists('/proc/cpuinfo'):
    try:
      f = open('/proc/cpuinfo')
      model_name = _get_value_for_key(f.readlines(), 'model name')
      if model_name:
        return model_name
    finally:
      f.close()
  return platform.processor()


def GetVersion():
  svn_info = _svn('info')
  if svn_info:
    revision = _get_value_for_key(svn_info.split('\n'), 'Revision')
    if revision:
      return revision
  return 'unknown'


class TestInstance:
  def __init__(self, network, log_level, record):
    self.network = network
    self.log_level = log_level
    self.record = record
    self.proxy_process = None
    self.spdy_proxy_process = None

  def GenerateConfigFile(self, notes=''):
    # The PerfTracker extension requires this name in order to kick off.
    ext_suffix = 'startbenchmark.html'
    self.filename = tempfile.mktemp(suffix=ext_suffix, prefix='')
    f = open(self.filename, 'w+')
    
    benchmark = {
      'user': getpass.getuser(),
      'notes': str(notes),
      'cmdline': ' '.join(sys.argv),
      'server_url': runner_cfg.appengine_url,
      'server_login': options.login_url,
      'client_hostname': platform.node(),
      'harness_version': GetVersion(),
      'cpu': GetCPU(),
      'iterations': str(runner_cfg.iterations),
      'download_bandwidth_kbps': str(self.network['bandwidth_kbps']['down']),
      'upload_bandwidth_kbps': str(self.network['bandwidth_kbps']['up']),
      'round_trip_time_ms': str(self.network['round_trip_time_ms']),
      'packet_loss_rate': str(self.network['packet_loss_percent']),
      'protocol': self.network['protocol'],
      'urls': runner_cfg.urls,
      'record': self.record
    }

    f.write("""
<body>
<h3>Running benchmark...</h3>
<script>
// Sometimes the extension doesn't load.
// Set a timer, if the extension didn't write an ACK into the status
// box, then reload this page.
setTimeout(function() {
  var status = document.getElementById("status");
  if (status.textContent != "ACK") {
    console.log("Benchmark stuck?  Reloading.");
    window.location.reload(true);
  }
}, 30000);
</script>
<textarea id=json style="width:100%%;height:80%%;">
%s
</textarea>
<textarea id=status></textarea>
</body>
""" % json.dumps(benchmark, indent=2))

    f.close()
    return

  def StartProxy(self):
    log_level = 'info'
    if self.log_level:
      log_level = self.log_level
    # To run SPDY, we use the SPDY-to-HTTP gateway.  The gateway will answer
    # on port |server_port|, contacting the backend server (the replay server)
    # which will run on |backend_server_port|.
    port = server_port
    init_cwnd = 10
    protocol = self.network['protocol']
    if 'spdy' in protocol:
        port = backend_server_port
        init_cwnd = 32

    if protocol == 'http-base':
        init_cwnd = 3   # See RFC3390

    cmdline = [
        replay_path,
        '-l', log_level,
        '--no-dns_forwarding',
        '--no-deterministic_script',
        '--port', str(port),
        '--shaping_port', str(server_port),
        '--init_cwnd', str(init_cwnd),
        ]
    if self.network['bandwidth_kbps']['down']:
      cmdline += ['-d', str(self.network['bandwidth_kbps']['down']) + 'KBit/s']
    if self.network['bandwidth_kbps']['up']:
      cmdline += ['-u', str(self.network['bandwidth_kbps']['up']) + 'KBit/s']
    if self.network['round_trip_time_ms']:
      cmdline += ['-m', str(self.network['round_trip_time_ms'])]
    if self.network['packet_loss_percent']:
      cmdline += ['-p', str(self.network['packet_loss_percent'] / 100.0)]
    if self.record:
      cmdline.append('-r')
    cmdline.append(runner_cfg.replay_data_archive)

    logging.debug('Starting Web-Page-Replay: %s', ' '.join(cmdline))
    self.proxy_process = subprocess.Popen(cmdline)

  def StopProxy(self):
    if self.proxy_process:
      logging.debug('Stopping Web-Page-Replay')
      # Use a SIGINT here so that it can do graceful cleanup.
      # Otherwise we'll leave subprocesses hanging.
      self.proxy_process.send_signal(signal.SIGINT)
      self.proxy_process.wait()

  def StartSpdyProxy(self):
    certfile = ""
    keyfile = ""
    protocol = self.network['protocol']
    if protocol == "spdy":
      certfile = runner_cfg.ssl['certfile']
      keyfile = runner_cfg.ssl['keyfile']

    proxy_parameters = {
      "listen_host": "",
      "listen_port": server_port,
      "cert_file": certfile,
      "key_file": keyfile,
      "http_host": "127.0.0.1",
      "http_port": backend_server_port,
      "https_host": "",
      "https_port": "",
      "spdy_only": 0,
    }
    proxy_cfg = "--proxy1=%(listen_host)s,%(listen_port)d,%(cert_file)s,%(key_file)s,%(http_host)s,%(http_port)d,%(https_host)s,%(https_port)s,%(spdy_only)d" % proxy_parameters
    # TODO(mbelshe): Remove the logfile when done with debugging the flipserver.
    logfile = "/tmp/flipserver.log"
    try:
      os.remove(logfile)
    except:
      pass
    cmdline = [ 
      runner_cfg.spdy_proxy_server_path, proxy_cfg, 
      "--force_spdy",
      "--v=2",
      "--logfile=" + logfile
    ]
    logging.debug('Starting SPDY proxy: %s', ' '.join(cmdline))
    self.spdy_proxy_process = subprocess.Popen(cmdline,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT)

  def StopSpdyProxy(self):
    if self.spdy_proxy_process:
      logging.debug('Stopping SPDY Proxy')
      try:
        # For the SPDY server we kill it, because it has no dependencies.
        self.spdy_proxy_process.kill()
      except OSError:
        pass
      self.spdy_proxy_process.wait()

  def RunChrome(self, chrome_cmdline):
    start_file_url = 'file://' + self.filename

    profile_dir = tempfile.mkdtemp(prefix='chrome.profile.');

    use_virtualx = False
    if platform.system() == 'Linux':
      use_virtualx = True

    try:
      if use_virtualx:
        StartVirtualX(platform.node(), '/tmp')

      server_host_port_pair = '127.0.0.1:' + str(server_port)
      cmdline = [
          runner_cfg.chrome_path,
          '--activate-on-launch',
          '--disable-background-networking',
          # TODO(tonyg): These are disabled to reduce noise. It would be nice to
          # make the model realistic and stable enough to enable them.
          '--disable-preconnect',
          '--dns-prefetch-disable',

          '--enable-benchmarking',
          '--enable-logging',
          '--host-resolver-rules=MAP * ' + server_host_port_pair + ',EXCLUDE ' +
              runner_cfg.appengine_host, 
          '--ignore-certificate-errors',
          '--load-extension=' + perftracker_extension_path,
          '--log-level=0',
          '--no-first-run',
          '--no-js-randomness',
          '--no-proxy-server',
          '--start-maximized',
          '--user-data-dir=' + profile_dir,
          ]

      spdy_mode = None
      if self.network['protocol'] == 'spdy':
        spdy_mode = 'ssl'
      if self.network['protocol'] == 'spdy-nossl':
        spdy_mode = 'no-ssl'
      if spdy_mode:
        cmdline.extend(['--use-spdy=' + spdy_mode + ',exclude=' +
                        runner_cfg.appengine_url])
      if chrome_cmdline:
        cmdline.extend(chrome_cmdline.split(' '))
      cmdline.append(start_file_url)

      logging.debug('Starting Chrome: %s', ' '.join(cmdline))
      chrome = subprocess.Popen(cmdline)
      returncode = chrome.wait();
      if returncode:
        logging.error('Chrome returned status code %d. It may have crashed.' % returncode)
    finally:
      ClobberTmpDirectory(profile_dir)
      if use_virtualx:
        StopVirtualX(platform.node())

  def RunTest(self, notes, chrome_cmdline):
    try:
      self.GenerateConfigFile(notes)
      self.StartProxy()
      protocol = self.network['protocol']
      if 'spdy' in protocol:
        self.StartSpdyProxy()
      self.RunChrome(chrome_cmdline)
    finally:
      logging.debug('Cleaning up test')
      self.StopProxy()
      self.StopSpdyProxy()
      self.Cleanup()

  def Cleanup(self):
    os.remove(self.filename)

def main(options):
  # When in record mode, override most of the configuration.
  if options.record:
    runner_cfg.replay_data_archive = options.record
    runner_cfg.iterations = 1
    runner_cfg.networks = [
      {
        'bandwidth_kbps': {
          'up': 0,
          'down': 0
        },
        'round_trip_time_ms': 0,
        'packet_loss_percent': 0,
        'protocol': 'http',
      }
    ]

  done = False
  while not done:
    for network in runner_cfg.networks:
      logging.debug("Running network configuration: %s", str(network))
      test = TestInstance(network, options.log_level, options.record)
      test.RunTest(options.notes, options.chrome_cmdline)
    if not options.infinite or options.record:
      done = True

    if runner_cfg.inter_run_cleanup_script and not options.record:
      logging.debug("Running inter-run-cleanup-script")
      subprocess.call([runner_cfg.inter_run_cleanup_script], shell=True)

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
  option_parser.add_option('-r', '--record', default='',
      action='store',
      type='string',
      help=('If specified, rather than running benchmark, record URLs in config'
            'to given file.'))
  option_parser.add_option('-i', '--infinite', default=False,
      action='store_true',
      help='Loop infinitely, repeating the test.')
  option_parser.add_option('-o', '--chrome_cmdline', default=None,
      action='store',
      type='string',
      help='Command line options to pass to chrome.')
  option_parser.add_option('-n', '--notes', default='',
      action='store',
      type='string',
      help='Notes to record with this test run.')
  option_parser.add_option('-u', '--user', default=None,
      action='store',
      type='string',
      help='Username for logging into appengine.')

  options, args = option_parser.parse_args()

  # Collect login credentials and verify
  if options.user:
    options.password = getpass.getpass(options.user + ' password: ');
    options.login_url = DoAppEngineLogin(options.user, options.password)
    if not options.login_url:
      exit(-1)
  elif runner_cfg.appengine_host != 'localhost':
    option_parser.error('Must specify an appengine user for login')
    exit(-1)
  else:
    options.login_url = ''

  log_level = logging.__dict__[options.log_level.upper()]
  logging.basicConfig(level=log_level)
  if options.log_file:
    fh = logging.FileHandler(options.log_file)
    fh.setLevel(log_level)
    logging.getLogger('').addHandler(fh)

  sys.exit(main(options))

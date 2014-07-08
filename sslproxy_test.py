"""Test routines to generate dummy certificates."""

import BaseHTTPServer
import shutil
import signal
import socket
import tempfile
import threading
import time
import unittest

import certutils
from OpenSSL import SSL
import sslproxy

signal.signal(signal.SIGINT, signal.SIG_DFL)  # Exit on Ctrl-C

error_function = None


class Client(object):

  def __init__(self, method, ca_path, verify_cb, port, host_name,
               host='localhost'):
    self.method = method
    self.verify_cb = verify_cb
    self.ca_path = ca_path
    self.port = port
    self.host_name = host_name
    self.host = host
    self.connection = None

  def run_request(self):
    context = SSL.Context(self.method)
    context.set_verify(SSL.VERIFY_PEER, self.verify_cb)  # Demand a certificate
    context.use_certificate_file(self.ca_path)
    context.load_verify_locations(self.ca_path)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connection = SSL.Connection(context, s)
    self.connection.connect((self.host, self.port))
    self.connection.set_tlsext_host_name(self.host_name)

    self.connection.send('GET / HTTP/1.1\r\nHost: google.com:443\r\n\r\n')

    while True:
      try:
        self.connection.recv(65537)
      except Exception:
        pass
      break

  def shutDown(self):
    self.connection.shutdown()
    self.connection.close()


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
  protocol_version = 'HTTP/1.1'  # override BaseHTTPServer setting

  def handle_one_request(self):
    """Handle a single HTTP request."""
    self.raw_requestline = self.rfile.readline(65537)


class Server(BaseHTTPServer.HTTPServer):
  """SSL server."""

  def __init__(self, port, cert_file, use_sslproxy_wrapper=True,
               host='localhost'):
    if use_sslproxy_wrapper:
      self.HANDLER = sslproxy.wrap_handler(Handler, cert_file)
    else:
      sslproxy.set_ca_cert(cert_file)
      self.HANDLER = WrappedErrorHandler
    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), self.HANDLER)
    except Exception, e:
      raise 'Could not start HTTPSServer on port %d: %s' % (port, e)

  def __enter__(self):
    thread = threading.Thread(target=self.serve_forever)
    thread.daemon = True
    thread.start()
    return self

  def cleanup(self):
    try:
      self.shutdown()
    except KeyboardInterrupt:
      pass
    sslproxy.cert_store.cleanup()

  def __exit__(self):
    self.cleanup()


class WrappedErrorHandler(sslproxy.SSLHandshakeHandler, Handler):
  """Wraps handler to verify expected sslproxy errors are being raised."""

  def setup(self):
    Handler.setup(self)
    try:
      sslproxy.SSLHandshakeHandler.setup(self)
    except SSL.Error:
      global error_function
      error_function = SSL.Error

  def finish(self):
    sslproxy.SSLHandshakeHandler.finish(self)
    Handler.finish(self)


class TestClient(unittest.TestCase):
  _temp_dir = None

  def setUp(self):
    self._temp_dir = tempfile.mkdtemp(prefix='sslproxy_', dir='/tmp')

    self.ca = self._temp_dir + 'testCA.pem'
    self.cert = self._temp_dir + 'testCA-cert.cer'
    self.wrong_ca = self._temp_dir + 'wrong.pem'
    self.wrong_cert = self._temp_dir + 'wrong-cert.cer'

    c, k = certutils.generate_dummy_ca()
    certutils.write_dummy_ca(self.ca, c, k)

    c, k = certutils.generate_dummy_ca()
    certutils.write_dummy_ca(self.wrong_ca, c, k)

  def tearDown(self):
    global error_function
    error_function = None
    if self._temp_dir:
      shutil.rmtree(self._temp_dir)

  def _verify_cb(self, conn, cert, errnum, depth, ok):
    """A callback that verifies the certificate authentication worked.

    Args:
      conn: Connection object
      cert: x509 object
      errnum: possible error number
      depth: error depth
      ok: return 1 if the verification worked 0 if it didn't
    """
    self.ok = ok
    self.assertFalse(cert.has_expired())
    self.assertGreater(time.strftime('%Y%m%d%H%M%SZ', time.gmtime()),
                       cert.get_notBefore())
    return ok

  def startServer(self, port, use_sslproxy_wrapper=False):
    self.s = Server(port, self.ca, use_sslproxy_wrapper)
    self.s.__enter__()

  def stopServer(self):
    self.s.__exit__()

  def test_no_host(self):
    port = 12345
    self.startServer(port)

    c = Client(SSL.SSLv23_METHOD, self.cert, self._verify_cb, port, '')
    self.assertRaises(SSL.Error, c.run_request)
    c.shutDown()

    self.stopServer()

  def test_no_ca(self):
    port = 12344
    self.assertRaises(ValueError, Server, port, 'no.pem')

  def test_client_connection(self):
    port = 12346
    self.startServer(port, True)

    c = Client(SSL.SSLv23_METHOD, self.cert, self._verify_cb, port, 'foo.com')
    c.run_request()
    self.assertTrue(self.ok)
    c.shutDown()

    c = Client(SSL.SSLv23_METHOD, self.cert, self._verify_cb, port,
               'random.host')
    c.run_request()
    self.assertTrue(self.ok)
    c.shutDown()

    self.stopServer

  def test_wrong_cert(self):
    port = 12347
    self.startServer(port)

    c = Client(SSL.SSLv23_METHOD, self.wrong_cert, self._verify_cb, port,
               'foo.com')
    self.assertRaises(SSL.Error, c.run_request)
    self.assertFalse(self.ok)
    c.shutDown()
    self.assertEqual(SSL.Error, error_function)
    self.stopServer()


if __name__ == '__main__':
  unittest.main()

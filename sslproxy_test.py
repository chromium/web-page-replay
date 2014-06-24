"""Test routines to generate dummy certificates."""

import BaseHTTPServer
import shutil
import signal
import socket
import tempfile
import threading
import time
import unittest

from OpenSSL import SSL
import sslproxy

import certutils

signal.signal(signal.SIGINT, signal.SIG_DFL)  # Exit on Ctrl-C


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

    self.connection.send('\r\n\r\n')

  def shutDown(self):
    self.connection.shutdown()
    self.connection.close()


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
  protocol_version = 'HTTP/1.1'  # override BaseHTTPServer setting

  def handle_one_request(self):
    """Handle a single HTTP request."""
    self.raw_requestline = self.rfile.readline(65537)


class DummyResponse(object):

  def __init__(self, response):
    self.response_data = response


class Server(BaseHTTPServer.HTTPServer):
  """SSL server."""

  def __init__(self, port, cert_file, use_sslproxy_wrapper=True,
               host='localhost'):
    self.ca = cert_file
    self.cert = ''
    if use_sslproxy_wrapper:
      self.HANDLER = sslproxy.wrap_handler(Handler)
    else:
      self.HANDLER = WrappedErrorHandler
    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), self.HANDLER)
    except Exception, e:
      raise 'Could not start HTTPSServer on port %d: %s' % (port, e)

  def http_archive_fetch(self, req):
    cert = certutils.generate_dummy_cert_from_file(self.ca, req.host)
    return DummyResponse(cert)

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

  def __exit__(self):
    self.cleanup()


class WrappedErrorHandler(sslproxy.SSLHandshakeHandler, Handler):
  """Wraps handler to verify expected sslproxy errors are being raised."""

  def setup(self):
    Handler.setup(self)
    try:
      sslproxy.SSLHandshakeHandler.setup(self)
    except SSL.Error:
      self.server.error_function = SSL.Error

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
    if self._temp_dir:
      shutil.rmtree(self._temp_dir)

  def verify_cb(self, conn, cert, errnum, depth, ok):
    """A callback that verifies the certificate authentication worked.

    Args:
      conn: Connection object
      cert: x509 object
      errnum: possible error number
      depth: error depth
      ok: 1 if the authentication worked 0 if it didnt.
    Returns:
      1 or 0 depending on if the verification worked
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

  def test__NoHost(self):
    port = 12345
    self.startServer(port)

    c = Client(SSL.SSLv23_METHOD, self.cert, self.verify_cb, port, '')
    self.assertRaises(SSL.Error, c.run_request)
    c.shutDown()

    self.stopServer()

  def test__ClientConnection(self):
    port = 12346
    self.startServer(port, True)

    c = Client(SSL.SSLv23_METHOD, self.cert, self.verify_cb, port, 'foo.com')
    c.run_request()
    self.assertTrue(self.ok)
    c.shutDown()

    c = Client(SSL.SSLv23_METHOD, self.cert, self.verify_cb, port,
               'random.host')
    c.run_request()
    self.assertTrue(self.ok)
    c.shutDown()

    self.stopServer

  def test__WrongCert(self):
    port = 12347
    self.startServer(port)

    c = Client(SSL.SSLv23_METHOD, self.wrong_cert, self.verify_cb, port,
               'foo.com')
    self.assertRaises(SSL.Error, c.run_request)
    self.assertFalse(self.ok)
    c.shutDown()
    self.assertEqual(SSL.Error, self.s.error_function)
    self.stopServer()


if __name__ == '__main__':
  unittest.main()

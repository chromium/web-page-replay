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

import certutils
import sslproxy


class Client(object):

  def __init__(self, pem_path, verify_cb, port, host_name='foo.com',
               host='localhost', method=SSL.SSLv23_METHOD):
    self.host_name = host_name
    self.method = method
    self.verify_cb = verify_cb
    self.pem_path = pem_path
    self.port = port
    self.host_name = host_name
    self.host = host
    self.connection = None

  def run_request(self):
    context = SSL.Context(self.method)
    context.set_verify(SSL.VERIFY_PEER, self.verify_cb)  # Demand a certificate
    context.use_certificate_file(self.pem_path)
    context.load_verify_locations(self.pem_path)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connection = SSL.Connection(context, s)
    self.connection.connect((self.host, self.port))
    self.connection.set_tlsext_host_name(self.host_name)

    try:
      self.connection.send('\r\n\r\n')
    finally:
      self.connection.shutdown()
      self.connection.close()


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
  protocol_version = 'HTTP/1.1'  # override BaseHTTPServer setting

  def handle_one_request(self):
    """Handle a single HTTP request."""
    self.raw_requestline = self.rfile.readline(65537)


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


class DummyResponse(object):

  def __init__(self, response):
    self.response_data = [response]


class Server(BaseHTTPServer.HTTPServer):
  """SSL server."""

  def __init__(self, pem_path, use_error_handler = False, port=0,
               host='localhost'):
    self.pem_path = pem_path
    with open(pem_path, 'r') as pem_file:
      self.root_pem = pem_file.read()
    self.crt = ''
    if use_error_handler:
      self.HANDLER = WrappedErrorHandler
    else: 
      self.HANDLER = sslproxy.wrap_handler(Handler)
    try:
      BaseHTTPServer.HTTPServer.__init__(self, (host, port), self.HANDLER)
    except Exception, e:
      raise RuntimeError('Could not start HTTPSServer on port %d: %s'
                         % (port, e))

  def http_archive_fetch(self, req):
    crt = certutils.generate_dummy_crt_from_server(
       self.root_pem, '', req.host)
    return DummyResponse(crt)

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

  def __exit__(self, type_, value_, traceback_):
    self.cleanup()


class TestClient(unittest.TestCase):
  _temp_dir = None

  def setUp(self):
    self._temp_dir = tempfile.mkdtemp(prefix='sslproxy_', dir='/tmp')

    self.pem_path = self._temp_dir + 'testCA.pem'
    self.cert_path = self._temp_dir + 'testCA-cert.cer'
    self.wrong_pem_path = self._temp_dir + 'wrong.pem'
    self.wrong_cert_path = self._temp_dir + 'wrong-cert.cer'

    # Write both pem and cer files for certificates
    certutils.write_dummy_ca( self.pem_path, *certutils.generate_dummy_ca())
    certutils.write_dummy_ca(self.wrong_pem_path, *certutils.generate_dummy_ca())

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
    self.assertFalse(cert.has_expired())
    self.assertGreater(time.strftime('%Y%m%d%H%M%SZ', time.gmtime()),
                       cert.get_notBefore())
    return ok

  def test_no_host(self):
    with Server(self.pem_path) as server:
      c = Client(self.cert_path, self.verify_cb, server.server_port, '')
      self.assertRaises(SSL.Error, c.run_request)

  def test_client_connection(self):
    with Server(self.pem_path) as server:
      c = Client(self.cert_path, self.verify_cb, server.server_port, 'foo.com')
      c.run_request()

      c = Client(self.cert_path, self.verify_cb, server.server_port,
                 'random.host')
      c.run_request()

  def test_wrong_cert(self):
    with Server(self.pem_path, True) as server:
      c = Client(self.wrong_cert_path, self.verify_cb, server.server_port,
                 'foo.com')
      self.assertRaises(SSL.Error, c.run_request)


if __name__ == '__main__':
  signal.signal(signal.SIGINT, signal.SIG_DFL)  # Exit on Ctrl-C
  unittest.main()

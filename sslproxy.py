"""Extends BaseHTTPRequestHandler with SSL certificate generation."""

import httparchive
import logging
import socket

openssl_import_error = None
try:
  # Requires: pyOpenSSL 0.13+
  from OpenSSL import crypto, SSL
except ImportError, e:
  openssl_import_error = e


def get_cert_request(host):
  return httparchive.ArchivedHttpRequest('DUMMY_CERT', host, '', None, {})

class SSLHandshakeHandler:
  """Handles Server Name Indication (SNI) using dummy certs."""
  past_certs = {}

  def setup(self):
    """Sets up connection providing the certificate to the client."""
    self.server_name = None
    # One of: One of SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, or TLSv1_METHOD
    context = SSL.Context(SSL.SSLv23_METHOD)
    def handle_servername(connection):
      """A SNI callback that happens during do_handshake()."""
      try:
        host = connection.get_servername()
        if host:
          certificate_request = get_cert_request(host)
          cert_response = self.server.http_archive_fetch(certificate_request)
          cert = cert_response.response_data
          self.server.cert = cert
          if cert:
            self.server_name = host
            new_context = SSL.Context(SSL.SSLv23_METHOD)
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            new_context.use_certificate(cert)
            new_context.use_privatekey_file(self.server.ca)
            connection.set_context(new_context)
            return new_context
        # else: fail with 'no shared cipher'
      except Exception, e:
        # Do not leak any exceptions or else openssl crashes.
        print('Exception in SNI handler', e)

    context.set_tlsext_servername_callback(handle_servername)
    self.connection = SSL.Connection(context, self.connection)
    self.connection.set_accept_state()
    try:
      self.connection.do_handshake()
    except SSL.Error, v:
      host = self.connection.get_servername()
      if not host or not self.server.cert:
        logging.error('Dropping request without SNI')
        return ''
      raise SSL.Error('SSL handshake error %s: %s' % (host, str(v)))

    def wrap_recv(recv):
      """Wraps recv to handle ragged EOFs and ZeroReturnErrors."""
      def wrapped_recv(buflen=1024, flags=0):
        try:
          return recv(buflen, flags)
        except SSL.SysCallError, e:
          if e.args[1] == 'Unexpected EOF':
            return ''
          raise
        except SSL.ZeroReturnError:
          return ''
      return wrapped_recv
    self.connection.recv = wrap_recv(self.connection.recv)

    # Re-wrap the read/write streams with our new connection.
    self.rfile = socket._fileobject(self.connection, 'rb', self.rbufsize,
                                    close=False)
    self.wfile = socket._fileobject(self.connection, 'wb', self.wbufsize,
                                    close=False)

  def finish(self):
    try:
      self.connection.shutdown()
    except:
      print 'shutdown'


def wrap_handler(handler_class, cert_file):
  """Wraps a BaseHTTPHandler wtih SSL MITM certificates."""
  if openssl_import_error:
    raise openssl_import_error

  class WrappedHandler(SSLHandshakeHandler, handler_class):

    def setup(self):
      handler_class.setup(self)
      SSLHandshakeHandler.setup(self)

    def finish(self):
      handler_class.finish(self)
      SSLHandshakeHandler.finish(self)
  return WrappedHandler

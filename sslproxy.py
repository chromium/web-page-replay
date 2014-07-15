"""Extends BaseHTTPRequestHandler with SSL certificate generation."""

import socket
import certutils

openssl_import_error = None
try:
  # Requires: pyOpenSSL 0.13+
  from OpenSSL import SSL
except ImportError, e:
  openssl_import_error = e

cert_store = None


class WrappedConnection(object):

  def __init__(self, obj):
    self._wrapped_obj = obj

  def __getattr__(self, attr):
    if attr in self.__dict__:
      return getattr(self, attr)
    return getattr(self._wrapped_obj, attr)

  def recv(self, buflen=1024, flags=0):
    try:
      return self._wrapped_obj.recv(buflen, flags)
    except SSL.SysCallError, e:
      if e.args[1] == 'Unexpected EOF':
        return ''
      raise
    except SSL.ZeroReturnError:
      return ''


def set_ca_cert(ca_cert):
  global cert_store
  cert_store = certutils.CertStore(ca_cert, cert_dir=None)


class SslHandshakeHandler:
  """Handles Server Name Indication (SNI) using dummy certs."""

  def setup(self):
    """Sets up connection providing the certificate to the client."""
    # One of: One of SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, or TLSv1_METHOD
    method = SSL.SSLv23_METHOD
    context = SSL.Context(method)
    def handle_servername(connection):
      """A SNI callback that happens during do_handshake()."""
      try:
        host = connection.get_servername()
        if host:
          cert = cert_store.get_cert(host)
          new_context = SSL.Context(SSL.SSLv23_METHOD)
          new_context.use_certificate_file(cert)
          new_context.use_privatekey_file(cert_store.ca_cert)
          connection.set_context(new_context)
          return new_context
        # else: fail with 'no shared cipher'
        # TODO(mruthven): move cert generation to after fetch so the host name
        # can be gotten from the server.
      except Exception, e:
        # Do not leak any exceptions or else openssl crashes.
        logging.error('Exception in SNI handler', e)

    context.set_tlsext_servername_callback(handle_servername)
    self.connection = WrappedConnection(SSL.Connection(context,
                                                       self.connection))
    self.connection.set_accept_state()
    try:
      self.connection.do_handshake()
    except SSL.Error, v:
      self.connection.shutdown()
      self.connection.close()
      raise Exception('SSL handshake error: %s' % str(v))

    # Re-wrap the read/write streams with our new connection.
    self.rfile = socket._fileobject(self.connection, 'rb', self.rbufsize,
                                    close=False)
    self.wfile = socket._fileobject(self.connection, 'wb', self.wbufsize,
                                    close=False)

  def finish(self):
    self.connection.shutdown()
    self.connection.close()


def wrap_handler(handler_class, cert_file):
  """Wraps a BaseHTTPHandler with SSL MITM certificates."""
  if openssl_import_error:
    raise openssl_import_error
  set_ca_cert(cert_file)

  class WrappedHandler(SslHandshakeHandler, handler_class):

    def setup(self):
      handler_class.setup(self)
      SslHandshakeHandler.setup(self)

    def finish(self):
      handler_class.finish(self)
      SslHandshakeHandler.finish(self)
  return WrappedHandler



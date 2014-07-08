"""Routines to generate root and server certificates.

Certificate Naming Conventions:
  ca:   a private crypto.X509  (w/ both the pub & priv keys)
  cert: a public crypto.X509  (w/ just the pub key)
  crt:  a public string (w/ just the pub cert)
  key:  a private crypto.PKey  (from ca or pem)
  pem:  a private string (w/ both the pub & priv certs)
"""
import logging
import os
import socket
import time

openssl_import_error = None

SSL_METHOD = None
VERIFY_PEER = None
SysCallError = None
Error = None
ZeroReturnError = None

try:
  from OpenSSL import crypto, SSL

  SSL_METHOD = SSL.SSLv23_METHOD
  VERIFY_PEER = SSL.VERIFY_PEER
  SysCallError = SSL.SysCallError
  Error = SSL.Error
  ZeroReturnError = SSL.ZeroReturnError
except ImportError, e:
  openssl_import_error = e


def get_ssl_context(method=SSL_METHOD):
  # One of: One of SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, or TLSv1_METHOD
  return SSL.Context(method)


def get_ssl_connection(context, connection):
  return SSL.Connection(context, connection)


def load_privatekey(key, filetype=crypto.FILETYPE_PEM):
  """Loads x509 private key object from string."""
  return crypto.load_privatekey(filetype, key)


def load_cert(crt, filetype=crypto.FILETYPE_PEM):
  """Loads x509 cert object from string."""
  return crypto.load_certificate(filetype, crt)


def dump_privatekey(key, filetype=crypto.FILETYPE_PEM):
  """Dumps x509 private key object to string."""
  return crypto.dump_privatekey(filetype, key)


def dump_cert(cert, filetype=crypto.FILETYPE_PEM):
  """Dumps x509 cert object to string."""
  return crypto.dump_certificate(filetype, cert)


def generate_dummy_ca(subject='sslproxy'):
  """Generates dummy certificate authority.

  Args:
    subject: a string representing the desired root cert issuer
  Returns:
    A tuple of the public key and the private key x509 objects for the root
    certificate
  """
  if openssl_import_error:
    raise openssl_import_error

  key = crypto.PKey()
  key.generate_key(crypto.TYPE_RSA, 1024)

  ca = crypto.X509()
  ca.set_serial_number(int(time.time()*10000))
  ca.set_version(2)
  ca.get_subject().CN = subject
  ca.get_subject().O = subject
  ca.gmtime_adj_notBefore(-60 * 60 * 24 * 365 * 2)
  ca.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 2)
  ca.set_issuer(ca.get_subject())
  ca.set_pubkey(key)
  ca.add_extensions([
      crypto.X509Extension('basicConstraints', True, 'CA:TRUE'),
      crypto.X509Extension('nsCertType', True, 'sslCA'),
      crypto.X509Extension('extendedKeyUsage', True,
                           ('serverAuth,clientAuth,emailProtection,'
                            'timeStamping,msCodeInd,msCodeCom,msCTLSign,'
                            'msSGC,msEFS,nsSGC')),
      crypto.X509Extension('keyUsage', False, 'keyCertSign, cRLSign'),
      crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=ca),
      ])
  ca.sign(key, 'sha1')
  return ca, key


def get_SNI_from_server(host):
  """Contacts server and gets SNI from the returned certificate."""
  certs = ['']
  def verify_cb(conn, cert, errnum, depth, ok):
    certs.append(cert)
    # say that the certificate was ok
    return 1

  context = SSL.Context(SSL.SSLv23_METHOD)
  context.set_verify(SSL.VERIFY_PEER, verify_cb)  # Demand a certificate
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  connection = SSL.Connection(context, s)
  try:
    connection.connect((host, 443))
    connection.send('')
  except SSL.SysCallError:
    pass
  except socket.gaierror:
    logging.debug('Host name is not valid')
  connection.shutdown()
  connection.close()
  cert = certs[-1]
  if cert:
    cert = dump_cert(cert)
  return cert


def write_dummy_ca(cert_path, ca, key):
  """Writes four certificate files.

  For example, if cert_path is "mycert.pem":
      mycert.pem - CA plus private key
      mycert-cert.pem - CA in PEM format
      mycert-cert.cer - CA for Android
      mycert-cert.p12 - CA in PKCS12 format for Windows devices
  Args:
    cert_path: path string such as "mycert.pem"
    ca: crypto X509 generated certificate
    key: crypto X509 generated private key
  """
  dirname = os.path.dirname(cert_path)
  if dirname and not os.path.exists(dirname):
    os.makedirs(dirname)

  root_path = os.path.splitext(cert_path)[0]
  pem_path = root_path + '-cert.pem'
  android_cer_path = root_path + '-cert.cer'
  windows_p12_path = root_path + '-cert.p12'

  pem_key = dump_privatekey(key)
  pem_ca = dump_cert(ca)

  # Dump the CA plus private key
  with open(cert_path, 'w') as f:
    f.write(pem_key)
    f.write(pem_ca)

  # Dump the certificate in PEM format
  with open(pem_path, 'w') as f:
    f.write(pem_ca)

  # Create a .cer file with the same contents for Android
  with open(android_cer_path, 'w') as f:
    f.write(pem_ca)

  # Dump the certificate in PKCS12 format for Windows devices
  with open(windows_p12_path, 'w') as f:
    p12 = crypto.PKCS12()
    p12.set_certificate(ca)
    p12.set_privatekey(key)
    f.write(p12.export())


def generate_dummy_crt(root_pem, server_crt, host):
  """Generates a crt with the sni field in server_crt signed by the root_pem.

  Args:
    root_pem: PEM formatted string representing the root cert
    server_crt: PEM formatted string representing cert
    host: host name to use if there is no server_crt
  Returns:
    a PEM formatted certificate string
  """

  if openssl_import_error:
    raise openssl_import_error
  common_name = host
  if server_crt:
    cert = load_cert(server_crt)
    common_name = cert.get_subject().commonName

  ca = load_cert(root_pem)
  key = load_privatekey(root_pem)

  req = crypto.X509Req()
  subj = req.get_subject()
  subj.CN = common_name
  req.set_pubkey(ca.get_pubkey())
  req.sign(key, 'sha1')

  cert = crypto.X509()
  cert.gmtime_adj_notBefore(-60 * 60)
  cert.gmtime_adj_notAfter(60 * 60 * 24 * 30)
  cert.set_issuer(ca.get_subject())
  cert.set_subject(req.get_subject())
  cert.set_serial_number(int(time.time()*10000))
  cert.set_pubkey(req.get_pubkey())
  cert.sign(key, 'sha1')

  return dump_cert(cert)

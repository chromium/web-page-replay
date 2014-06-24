"""Routines to generate dummy certificates."""

import os
import shutil
import tempfile
import time

openssl_import_error = None
try:
  from OpenSSL import crypto, SSL
except ImportError, e:
  openssl_import_error = e


def generate_dummy_ca(subject='sslproxy'):
  """Generates dummy certificate authority."""
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

  pem_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
  pem_ca = crypto.dump_certificate(crypto.FILETYPE_PEM, ca)

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


def generate_dummy_cert_from_file(ca, common_name):
  """Generates a certificate for |common_name| signed by |ca| in |path|."""
  if openssl_import_error:
    raise openssl_import_error
  with open(ca, 'r') as ca_file:
    raw = ca_file.read()
  return generate_dummy_cert(raw, common_name)

def generate_dummy_cert_from_server(root_cert, server_cert):
  cert = crypto.load_certificate(crypto.FILETYPE_PEM, server_cert)
  sni = cert.get_subject().commonName
  return generate_dummy_cert(root_cert, sni)


def generate_dummy_cert(root_cert, common_name):
  ca = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert)
  key = crypto.load_privatekey(crypto.FILETYPE_PEM, root_cert)

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

  return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

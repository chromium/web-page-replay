"""Routines to generate dummy certificates."""

import os
import shutil
import tempfile
import time

openssl_exception = None
try:
  from OpenSSL import crypto
except ImportError, e:
  openssl_exception = e


def generate_dummy_ca():
  """Generates dummy certificate authority."""
  if openssl_exception:
    raise openssl_exception

  key = crypto.PKey()
  key.generate_key(crypto.TYPE_RSA, 1024)

  ca = crypto.X509()
  ca.set_serial_number(int(time.time()*10000))
  ca.set_version(2)
  ca.get_subject().CN = 'sslproxy'
  ca.get_subject().O = 'sslproxy'
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
  """ Writes four certificate files. For example, if cert_path is "mycert.pem":
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
  with open(pem_path , 'w') as f:
    f.write(pem_ca)

  # Create a .cer file with the same contents for Android
  with open(android_cer_path , 'w') as f:
    f.write(pem_ca)

  # Dump the certificate in PKCS12 format for Windows devices
  with open(windows_p12_path , 'w') as f:
    p12 = crypto.PKCS12()
    p12.set_certificate(ca)
    p12.set_privatekey(key)
    f.write(p12.export())

def generate_dummy_cert(path, ca, common_name):
  """Generates a certificate for |common_name| signed by |ca| in |path|."""
  if openssl_exception:
    raise openssl_exception
  raw = open(ca, 'r').read()
  ca = crypto.load_certificate(crypto.FILETYPE_PEM, raw)
  key = crypto.load_privatekey(crypto.FILETYPE_PEM, raw)

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

  with open(path, 'w') as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


class CertStore(object):
  """Implements an on-disk certificate store."""

  def __init__(self, ca_cert, cert_dir=None):
    if not os.path.exists(ca_cert):
      ca, key = generate_dummy_ca()
      write_dummy_ca(ca_cert, ca, key)
    self.ca_cert = ca_cert
    if cert_dir:
      self.is_temporary_cert_store = False
      self.cert_dir = cert_dir
    else:
      self.is_temporary_cert_store = True
      self.cert_dir = tempfile.mkdtemp(prefix='certstore')

  def is_valid_domain(self, common_name):
    """Checks for valid domain."""
    try:
      common_name.decode('idna')
      common_name.decode('ascii')
    except:
      return False
    return ('..' not in common_name and '/' not in common_name)

  def get_cert(self, common_name):
    """Returns the path to the certificate for |common_name|."""
    if not self.is_valid_domain(common_name):
      return None
    path = os.path.join(self.cert_dir, common_name + '.pem')
    if not os.path.exists(path):
      generate_dummy_cert(path, self.ca_cert, common_name)
    return path

  def cleanup(self):
    if self.is_temporary_cert_store:
      shutil.rmtree(self.cert_dir)

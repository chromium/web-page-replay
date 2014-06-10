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


def generate_dummy_ca(path):
  """Generates dummy certificate authority and writes it to file."""
  if openssl_exception:
    raise openssl_exception
  dirname = os.path.dirname(path)
  if not os.path.exists(dirname):
    os.makedirs(dirname)
  if path.endswith('.pem'):
    basename, _ = os.path.splitext(path)
    basename = os.path.basename(basename)
  else:
    basename = os.path.basename(path)

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

  # Dump the CA plus private key
  with open(path, 'w') as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))

  # Dump the certificate in PEM format
  with open(os.path.join(dirname, basename + '-cert.pem'), 'w') as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))

  # Create a .cer file with the same contents for Android
  with open(os.path.join(dirname, basename + '-cert.cer'), 'w') as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))

  # Dump the certificate in PKCS12 format for Windows devices
  with open(os.path.join(dirname, basename + '-cert.p12'), 'w') as f:
    p12 = crypto.PKCS12()
    p12.set_certificate(ca)
    p12.set_privatekey(key)
    f.write(p12.export())


def generate_dummy_cert(path, ca, commonname):
  """Generates a certificate for |commonname| signed by |ca| in |path|."""
  if openssl_exception:
    raise openssl_exception
  raw = open(ca, 'r').read()
  ca = crypto.load_certificate(crypto.FILETYPE_PEM, raw)
  key = crypto.load_privatekey(crypto.FILETYPE_PEM, raw)

  req = crypto.X509Req()
  subj = req.get_subject()
  subj.CN = commonname
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

  def __init__(self, cacert, certdir=None):
    if not os.path.exists(cacert):
      generate_dummy_ca(cacert)
    self.cacert = cacert
    if certdir:
      self.remove = False
      self.certdir = certdir
    else:
      self.remove = True
      self.certdir = tempfile.mkdtemp(prefix='certstore')

  def check_domain(self, commonname):
    """Checks for valid domain."""
    try:
      commonname.decode('idna')
      commonname.decode('ascii')
    except:
      return False
    if '..' in commonname:
      return False
    if '/' in commonname:
      return False
    return True

  def get_cert(self, commonname):
    """Returns the path to the certificate for |commonname|."""
    if not self.check_domain(commonname):
      return None
    path = os.path.join(self.certdir, commonname + '.pem')
    if not os.path.exists(path):
      generate_dummy_cert(path, self.cacert, commonname)
    return path

  def cleanup(self):
    if self.remove:
      shutil.rmtree(self.certdir)

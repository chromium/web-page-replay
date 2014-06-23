"""Test routines to generate dummy certificates."""

import os
import shutil
import tempfile
import unittest

import certutils
from OpenSSL import crypto


class CertutilsTest(unittest.TestCase):

  def checkCertFile(self, cert_file_path, cert, key=None):
    raw_cert = open(cert_file_path, 'r').read()
    cert_load = crypto.load_certificate(crypto.FILETYPE_PEM, raw_cert)
    self.assertX509IsEqual(cert, cert_load, crypto.dump_certificate)
    if key:
      key_load = crypto.load_privatekey(crypto.FILETYPE_PEM, raw_cert)
      self.assertX509IsEqual(key_load, key, crypto.dump_privatekey)

  def assertX509IsEqual(self, a, b, dump_function):
    pem = crypto.FILETYPE_PEM
    self.assertEqual(dump_function(pem, a), dump_function(pem, b))

  def setUp(self):
    self._temp_dir = tempfile.mkdtemp(prefix='certutils_', dir='/tmp')

  def tearDown(self):
    if self._temp_dir:
      shutil.rmtree(self._temp_dir)

  def test__BadCertStoreCa(self):
    ca_cert = 'not.here'
    self.assertRaises(ValueError, certutils.CertStore, (ca_cert))

  def test__GenerateDummyCA(self):
    subject = 'testSubject'
    c, _ = certutils.generate_dummy_ca(subject)
    self.assertEqual(c.get_subject().commonName, subject)

  def test__WriteDummyCA(self):
    base_path = os.path.join(self._temp_dir, 'testCA')
    ca_path = base_path + '.pem'
    ca_pem = base_path + '-cert.pem'
    ca_android = base_path + '-cert.cer'
    ca_windows = base_path + '-cert.p12'

    self.assertFalse(os.path.exists(ca_path))
    self.assertFalse(os.path.exists(ca_pem))
    self.assertFalse(os.path.exists(ca_android))
    self.assertFalse(os.path.exists(ca_windows))

    c, k = certutils.generate_dummy_ca()
    certutils.write_dummy_ca(ca_path, c, k)

    self.checkCertFile(ca_path, c, k)
    self.checkCertFile(ca_pem, c)
    self.checkCertFile(ca_android, c)
    self.assertTrue(os.path.exists(ca_windows))

  def test__CertStore(self):
    ca_path = os.path.join(self._temp_dir, 'testCA.pem')
    cert, key = certutils.generate_dummy_ca()
    certutils.write_dummy_ca(ca_path, cert, key)
    cert_store = certutils.CertStore(ca_path)
    cert_dir = cert_store.cert_dir

    # Test cleanup
    self.assertTrue(os.path.exists(cert_dir))
    cert_store.cleanup()
    self.assertFalse(os.path.exists(cert_dir))


if __name__ == '__main__':
  unittest.main()

"""Test routines to generate dummy certificates."""
import unittest
import certutils
from OpenSSL import crypto
import tempfile
import os


class CertutilsTest(unittest.TestCase):
  _temp_file = None

  def setUp(self):
    if not self._temp_file:
      self._temp_file = tempfile.mkdtemp(prefix = 'certutils_', dir='/tmp')

  def tearDown(self):
    for fn in os.listdir(self._temp_file):
      os.remove(os.path.join(self._temp_file, fn))

  def test__BadCertStoreCa(self):
    ca_cert = 'not.here'
    self.assertRaises(ValueError, certutils.CertStore, (ca_cert))

  def test__GenerateDummyCA(self):
    subject = 'testSubject'
    c, _ = certutils.generate_dummy_ca(subject)
    self.assertEqual(c.get_subject().commonName, subject)

  def test__WriteDummyCA(self):
    base_path = os.path.join(self._temp_file, 'testCA')
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
    ca_path = os.path.join(self._temp_file, 'testCA.pem')
    cert, key = certutils.generate_dummy_ca()
    certutils.write_dummy_ca(ca_path, cert, key)
    cert_store = certutils.CertStore(ca_path)
    cert_dir = cert_store.cert_dir

    # Test cleanup
    self.assertTrue(os.path.exists(cert_dir))
    cert_store.cleanup()
    self.assertFalse(os.path.exists(cert_dir))

  def checkCertFile(self, path, cert, key=None):
    raw = open(path,'r').read()
    cert_load = crypto.load_certificate(crypto.FILETYPE_PEM, raw)
    self.assertX509IsEqual(cert, cert_load, crypto.dump_certificate)
    if key:
      key_load = crypto.load_privatekey(crypto.FILETYPE_PEM, raw)
      self.assertX509IsEqual(key_load, key, crypto.dump_privatekey)

  def assertX509IsEqual(self, a, b, dump):
    pem = crypto.FILETYPE_PEM
    self.assertEqual(dump(pem, a), dump(pem, b))

if __name__ == '__main__':
  unittest.main()

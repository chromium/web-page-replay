"""Test routines to generate dummy certificates."""

import os
import shutil
import tempfile
import unittest

import certutils
from OpenSSL import crypto


class CertutilsTest(unittest.TestCase):

  def _check_cert_file(self, cert_file_path, cert, key=None):
    raw_cert = open(cert_file_path, 'r').read()
    cert_load = crypto.load_certificate(crypto.FILETYPE_PEM, raw_cert)
    self._assert_x509_is_equal(cert, cert_load, crypto.dump_certificate)
    if key:
      key_load = crypto.load_privatekey(crypto.FILETYPE_PEM, raw_cert)
      self._assert_x509_is_equal(key_load, key, crypto.dump_privatekey)

  def _assert_x509_is_equal(self, a, b, dump_function):
    pem = crypto.FILETYPE_PEM
    self.assertEqual(dump_function(pem, a), dump_function(pem, b))

  def setUp(self):
    self._temp_dir = tempfile.mkdtemp(prefix='certutils_', dir='/tmp')

  def tearDown(self):
    if self._temp_dir:
      shutil.rmtree(self._temp_dir)

  def test_generate_dummy_ca(self):
    subject = 'testSubject'
    c, _ = certutils.generate_dummy_ca(subject)
    self.assertEqual(c.get_subject().commonName, subject)

  def test_write_dummy_ca(self):
    base_path = os.path.join(self._temp_dir, 'testCA')
    pem_path = base_path + '.pem'
    cert_path = base_path + '-cert.pem'
    ca_android = base_path + '-cert.cer'
    ca_windows = base_path + '-cert.p12'

    self.assertFalse(os.path.exists(pem_path))
    self.assertFalse(os.path.exists(cert_path))
    self.assertFalse(os.path.exists(ca_android))
    self.assertFalse(os.path.exists(ca_windows))

    c, k = certutils.generate_dummy_ca()
    certutils.write_dummy_ca(pem_path, c, k)

    self._check_cert_file(pem_path, c, k)
    self._check_cert_file(cert_path, c)
    self._check_cert_file(ca_android, c)
    self.assertTrue(os.path.exists(ca_windows))

  def test_generate_cert(self):
    pem_path = os.path.join(self._temp_dir, 'testCA.pem')
    issuer = 'testIssuer'
    cert, key = certutils.generate_dummy_ca(issuer)
    certutils.write_dummy_ca(pem_path, cert, key)

    with open(pem_path, 'r') as root_file:
      root_string = root_file.read()
    subject = 'testSubject'
    cert_string = certutils.generate_dummy_crt_from_server(
        root_string, '', subject)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string)
    self.assertEqual(issuer, cert.get_issuer().commonName)
    self.assertEqual(subject, cert.get_subject().commonName)

    with open(pem_path, 'r') as ca_file:
      pem = ca_file.read()
    cert_string = certutils.generate_dummy_crt_from_server(pem, cert_string,
                                                            'host')
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string)
    self.assertEqual(issuer, cert.get_issuer().commonName)
    self.assertEqual(subject, cert.get_subject().commonName)



if __name__ == '__main__':
  unittest.main()

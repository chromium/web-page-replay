"""Installs certificate on phone with KitKat."""
import argparse
import logging
import os
import subprocess
import sys

KEYCODE_ENTER = '66'
KEYCODE_TAB = '61'


class AndroidCertInstaller(object):
  """Certificate installer for phones with KitKat."""

  def __init__(self, device_id, cert_name, cert_path):
    if not os.path.exists(cert_path):
      raise ValueError('Not a valid certificate path')
    self.device_id = device_id
    self.cert_name = cert_name
    self.cert_path = cert_path
    self.file_name = os.path.basename(self.cert_path)

  def _adb(self, *args):
    """Runs the adb command."""
    cmd = ['adb']
    if self.device_id:
      cmd.extend(['-s', self.device_id])
    cmd.extend(args)
    return subprocess.check_output(cmd)

  def _get_property(self, prop):
    return self._adb('shell', 'getprop', prop).strip()

  def check_device(self):
    install_warning = False
    if self._get_property('ro.product.device') != 'hammerhead':
      logging.warning('Device is not hammerhead')
      install_warning = True
    if self._get_property('ro.build.version.release') != '4.4.2':
      logging.warning('Version is not 4.4.2')
      install_warning = True
    if install_warning:
      logging.warning('Certificate may not install properly')

  def _input_key(self, key):
    """Inputs a keyevent."""
    self._adb('shell', 'input', 'keyevent', key)

  def _input_text(self, text):
    self._adb('shell', 'input', 'text', text)

  def install_cert(self):
    """Installs certificate on the device using adb commands."""
    # TODO: Add a check to see if the certificate is already installed
    # Install the certificate.
    logging.info('Installing %s on %s', self.cert_path, self.device_id)
    self._adb('push', self.cert_path, '/sdcard/')

    # Start credential install intent.
    self._adb('shell', 'am', 'start', '-W', '-a', 'android.credentials.INSTALL')

    # Move to and click search button.
    self._input_key(KEYCODE_TAB)
    self._input_key(KEYCODE_TAB)
    self._input_key(KEYCODE_ENTER)

    # Search for certificate and click it.
    # Search only works with lower case letters
    self._input_text(self.file_name.lower())
    self._input_key(KEYCODE_ENTER)

    # These coordinates work for hammerhead devices.
    self._adb('shell', 'input', 'tap', '300', '300')

    # Name the certificate and click enter.
    self._input_text(self.cert_name)
    self._input_key(KEYCODE_TAB)
    self._input_key(KEYCODE_TAB)
    self._input_key(KEYCODE_TAB)
    self._input_key(KEYCODE_ENTER)

    # Remove the file.
    self._adb('shell', 'rm', '/sdcard/' + self.file_name)


def parse_args():
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(description='Install cert on device.')
  parser.add_argument(
      '-n', '--cert-name', default='dummycert', help='certificate name')
  parser.add_argument(
      '--device-id', help='device serial number')
  parser.add_argument(
      'cert_path', help='Certificate file path')
  return parser.parse_args()


def main():
  args = parse_args()
  cert_installer = AndroidCertInstaller(args.device_id, args.cert_name,
                                        args.cert_path)
  cert_installer.check_device()
  cert_installer.install_cert()


if __name__ == '__main__':
  sys.exit(main())

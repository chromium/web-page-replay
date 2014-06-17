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

  def _run_pipe_cmd(self, cmd):
    return subprocess.check_output(' '.join(cmd), shell=True)

  def _run_cmd(self, cmd):
    return subprocess.check_output(cmd)

  def _adb(self, *args):
    """Runs the adb command."""
    cmd = ['adb']
    if self.device_id:
      cmd.extend(['-s', self.device_id])
    cmd.extend(args)
    return subprocess.check_output(cmd)

  def _adb_su_shell(self, *args):
    """Runs command as root."""
    cmd = ['shell', 'su', '-c']
    cmd.extend(args)
    return self._adb(*cmd)

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
    """Inputs text."""
    self._adb('shell', 'input', 'text', text)

  def _get_file_length(self, file_name):
    return (int)(self._run_cmd(['wc', '-l', file_name]).split(' ')[0])

  def _remove(self, file_name):
    """Deletes file."""
    if os.path.exists(file_name):
      self._run_cmd(['rm', file_name])

  def _remove_cert_from_end(self, file_name):
    """Removes the certificate from the end of a file."""
    ca_length = self._get_file_length(self.cert_path)
    file_length = self._get_file_length(file_name)

    temp_file = 'temp_' + file_name
    self._run_pipe_cmd(['head', '-%i' % (file_length - ca_length), file_name,
                        '>', temp_file])
    self._run_cmd(['mv', temp_file, file_name])

  def _generate_hashed_cert(self):
    """Makes a certificate file that follows the format of files in cacerts."""
    output = self._run_cmd(['openssl', 'x509', '-inform', 'PEM',
                            '-subject_hash_old', '-in', self.cert_path])
    self.reformatted_cert_file = output.partition('\n')[0].strip() + '.0'

    self._remove(self.reformatted_cert_file)

    self._run_pipe_cmd(['cat', self.cert_path, '>', self.reformatted_cert_file])
    self._run_pipe_cmd(['openssl', 'x509', '-inform', 'PEM', '-text', '-in',
                        self.cert_path, '>>', self.reformatted_cert_file])

    self._remove_cert_from_end(self.reformatted_cert_file)

  def _remove_cert_from_cacerts(self):
    self._adb_su_shell('rm', self.android_cacerts_path)

  def cert_is_installed(self):
    ls_of_file = self._adb_su_shell('ls', self.android_cacerts_path)
    return ls_of_file.strip() == self.android_cacerts_path

  def install_cert(self, overwrite_cert=False):
    """Installs a certificate putting it in /system/etc/security/cacerts."""
    self._generate_hashed_cert()

    self.android_cacerts_path = ('/system/etc/security/cacerts/%s'
                                 % self.reformatted_cert_file)

    if self.cert_is_installed():
      if overwrite_cert:
        self._remove_cert_from_cacerts()
      else:
        logging.info('cert is already installed')
        return

    self._adb('push', self.reformatted_cert_file, '/sdcard/')
    self._adb_su_shell('mount', '-o', 'remount,rw', '/system')
    self._adb_su_shell('cp', '/sdcard/%s' % self.reformatted_cert_file,
                       self.android_cacerts_path)
    self._adb_su_shell('chmod', '644', self.android_cacerts_path)
    if not self.cert_is_installed():
      logging.warning('Cert Install Failed')

  def install_cert_using_gui(self):
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

"""Installs certificate on phone with KitKat."""
import argparse
import os
import subprocess
import sys

TAB_KEY = 61
ENTER_KEY = 66


class AndroidCertInstaller(object):
  """Certificate installer for phones with KitKat."""

  def __init__(self, args):
    if not os.path.exists(args.cert_path):
      raise ValueError('Not a valid certificate path')
    self.device_id = args.device_id
    self.cert_name = args.cert_name
    self.cert_path = args.cert_path
    self.file_name = os.path.basename(self.cert_path)

  def adb(self, command_arg):
    """Runs the adb command."""
    cmd = ['adb']
    if self.device_id:
      cmd.extend(['-s', self.device_id])
    cmd.extend(command_arg.split(' '))
    return subprocess.check_output(cmd)

  def input_key(self, key):
    """Inputs a keyevent."""
    self.adb('shell input keyevent %i' %key)

  def install_cert(self):
    """Installs certificate on the device using adb commands."""
    # Update certificate
    print 'Installing %s on %s' %(self.cert_path, self.device_id)
    self.adb('push %s /sdcard/' %self.cert_path)

    # Start credential install intent.
    self.adb('shell am start -W -a android.credentials.INSTALL')

    # Move to and click search button.
    self.input_key(TAB_KEY)
    self.input_key(TAB_KEY)
    self.input_key(ENTER_KEY)

    # Search for certificate and click it.
    # Search only works with lower case letters
    self.adb('shell input text %s' %self.file_name.lower())
    self.input_key(ENTER_KEY)
    self.adb('shell input tap 300 300')

    # Name certificate and click enter
    self.adb('shell input text %s' %self.cert_name)
    self.input_key(TAB_KEY)
    self.input_key(TAB_KEY)
    self.input_key(TAB_KEY)
    self.input_key(ENTER_KEY)

    # remove the file
    self.adb('shell rm /sdcard/%s' %self.file_name)


def parse_args():
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(description='Install cert on device.')
  parser.add_argument('-s', dest='device_id', type=str,
                      help='device serial number')
  parser.add_argument('cert_path', type=str, help='Certificate file path')
  parser.add_argument('-n', dest='cert_name', type=str, default='dummycert',
                      help='certificate name')
  return parser.parse_args()


def main():
  args = parse_args()
  cert_installer = AndroidCertInstaller(args)
  if args.device_id:
    cert_installer.install_cert()


if __name__ == '__main__':
  sys.exit(main())

#!/usr/bin/env python
# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for proxyshaper.

Usage:
$ ./proxyshaper_test.py
"""

import proxyshaper
import unittest


VALID_RATES = (
    # input,       expected_bps
    ( '384Kbit/s',   384000),
    ('1536Kbit/s',  1536000),
    (   '1Mbit/s',  1000000),
    (   '5Mbit/s',  5000000),
    (  '2MByte/s', 16000000),
    (         '0',        0),
    (         '5',        5),
    (      384000,   384000),
    )

ERROR_RATES = (
    '1536KBit/s',  # Older versions of dummynet used capital 'B' for bytes.
    '1Mbyte/s',    # Require capital 'B' for bytes.
    '5bps',
    )


class GetBitsPerSecondTest(unittest.TestCase):
  def testConvertsValidValues(self):
    for dummynet_option, expected_bps in VALID_RATES:
      bps = proxyshaper.GetBitsPerSecond(dummynet_option)
      self.assertEqual(
          expected_bps, bps, 'Unexpected result for %s: %s != %s' % (
              dummynet_option, expected_bps, bps))

  def testRaisesOnUnexpectedValues(self):
    for dummynet_option in ERROR_RATES:
      self.assertRaises(proxyshaper.BandwidthValueError,
                        proxyshaper.GetBitsPerSecond, dummynet_option)


if __name__ == '__main__':
  unittest.main()

#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
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


import cPickle
import os

class PersistentMixin:
  """Mixin class which provides facilities for persisting and restoring."""

  @classmethod
  def AssertWritable(cls, filename):
    """Raises an IOError if filename is not writable."""
    persist_dir = os.path.dirname(os.path.abspath(filename))
    if not os.path.exists(persist_dir):
      raise IOError('Directory does not exist: %s' % persist_dir)
    if os.path.exists(filename):
      if not os.access(filename, os.W_OK):
        raise IOError('Need write permission on file: %s' % filename)
    elif not os.access(persist_dir, os.W_OK):
      raise IOError('Need write permission on directory: %s' % persist_dir)

  @classmethod
  def Load(cls, filename):
    """Load an instance from filename."""
    return cPickle.load(open(filename, 'rb'))

  def Persist(self, filename):
    """Persist all state to filename."""
    cPickle.dump(self, open(filename, 'wb'), cPickle.HIGHEST_PROTOCOL)

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

class HTTPArchive(object):
  def __init__(self):
    self.url_archives = {}

  def add(self, url_archive):
    self.url_archives[url_archive.key()] = url_archive

  def has(self, key):
    return self.url_archives.has_key(key)

  def get(self, key):
    if not self.has(key):
      return None
    return self.url_archives[key]

class URLArchive(object):
  def __init__(self, host, path, request_body, response):
    self.host = host
    self.path = path
    self.request_body = request_body
    self.response = response
    self.key = host + '\n' + path + '\n' + request_body

  def __cmp__(self, other):
    return self.key < other.key

  def host(self):
    return self.host

  def path(self):
    return self.path

  def request_body(self):
    return self.request_body

  def response(self):
    return self.response

  def key(self):
    return self.key

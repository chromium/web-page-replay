#!/usr/bin/env python

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

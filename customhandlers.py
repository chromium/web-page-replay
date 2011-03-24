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

import base64
import logging
import os

GENERATOR_URL_PREFIX = '/web-page-replay-generate-'
POST_IMAGE_URL_PREFIX = '/web-page-replay-post-image-'
IMAGE_DATA_PREFIX = 'data:image/png;base64,'


class CustomHandlers(object):

  def __init__(self, save_images_dir=None):
    if save_images_dir and not os.path.exists(save_images_dir):
      try:
        os.makedirs(save_images_dir)
      except:
        logging.error('%s does not exist and could not be created.',
                      save_images_dir)
        save_images_dir = None
    self.save_images_dir = save_images_dir

  def handle(self, request):
    """Handles special URLs needed for the benchmark.

    Args:
      request: an http request
    Returns:
      If request is for a special URL, a 3-digit integer like 404.
      Otherwise, None.
    """
    response_code = self.get_generator_url_response_code(request.path)
    if response_code:
      return response_code

    response_code = self.handle_possible_post_image(request)
    if response_code:
      return response_code

    return None

  def get_generator_url_response_code(self, request_path):
    """Parse special generator URLs for the embedded response code.

    Clients like perftracker can use URLs of this form to request
    a response with a particular response code.

    Args:
      request_path: a string like "/foo", or "/web-page-replay-generator-404"
    Returns:
      On a match, a 3-digit integer like 404.
      Otherwise, None.
    """
    prefix, response_code = request_path[:-3], request_path[-3:]
    if prefix == GENERATOR_URL_PREFIX and response_code.isdigit():
      return int(response_code)
    return None

  def handle_possible_post_image(self, request):
    """If sent, saves embedded image to local directory.

    Expects a special url containing the filename. If sent, saves the base64
    encoded request body as a PNG image locally. This feature is enabled by
    passing in save_images_dir to the initializer for this class.

    Args:
      request: an http request

    Returns:
      On a match, a 3-digit integer response code.
      False otherwise.
    """
    if not self.save_images_dir:
      return None

    prefix = request.path[:len(POST_IMAGE_URL_PREFIX)]
    basename = request.path[len(POST_IMAGE_URL_PREFIX):]
    if prefix != POST_IMAGE_URL_PREFIX or not basename:
      return None

    data = request.request_body
    if not data.startswith(IMAGE_DATA_PREFIX):
      logging.error('Unexpected image format for: %s', basename)
      return 400

    data = data[len(IMAGE_DATA_PREFIX):]
    png = base64.b64decode(data)
    filename = '%s/%s-%s.png' % (self.save_images_dir, request.host, basename)
    f = file(filename, 'w')
    f.write(png)
    f.close()
    return 200

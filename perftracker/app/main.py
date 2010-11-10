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

import cgi
import json
import models
import os

from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db

class JSONDataPage(webapp.RequestHandler):
    def get(self):
        if not users.get_current_user():
            self.response.out.write("[{}]")
            return

        resource_type = self.request.get("type")
        if not resource_type:
            self.response.out.write("[{}]")
            return

        # Do a query for the appropriate resource type.
        if resource_type == "rollup":
            query = models.TestRollup.all();
        elif resource_type == "result":
            query = models.TestResult.all();
        elif resource_type == "suite":
            query = models.TestSuite.all();
        else:
            self.response.out.write("[{}]")
            return

        query.order("-date")

        # Apply filters.
        if self.request.get("url_filter"):
            query.filter("url =", self.request.get("url_filter"))
        if self.request.get("rtt_filter"):
            query.filter("round_trip_time_ms =", int(self.request.get("rtt_filter")))
        if self.request.get("suite_id"):
            my_test = models.TestSuite.get(db.Key(self.request.get("suite_id")))
            results = my_test.rollups
            #query = models.TestRollup.gql("WHERE suite=:1 ORDER by url", self.request.get("suite_id"))
            #query.filter("suite =", self.request.get("suite_id"))

        results = query.fetch(100)

        self.response.out.write(json.encode(results))

# Create an entry in the store for a new test.
class TestSuitePage(webapp.RequestHandler):
    def get(self):
        if not users.get_current_user():
            self.redirect(users.create_login_url(self.request.uri))
            return

        my_key = self.request.get('id')
        if not my_key:
            self.response.out.write("Could not find test suite")
            return

        my_test = models.TestSuite.get(db.Key(my_key))
        if not my_test:
            self.response.out.write("Could not find test suite")
            return

        test_result_query = models.TestResult.gql("WHERE suite=:1 ORDER by url", my_test.key())
        test_results = test_result_query.fetch(1000);

        template_values = {"suite": my_test,
                           "test_results": test_results}

        path = os.path.join(os.path.dirname(__file__), 'view_test_suite.html')
        self.response.out.write(template.render(path, template_values))

    def post(self):
        user = users.get_current_user()
        #if not user:
        #    self.redirect(users.create_login_url(self.request.uri))
        #    return

        test_suite = models.TestSuite(user=user)
        test_suite.notes = self.request.get('notes')
        test_suite.cmdline  = self.request.get('cmdline')
        test_suite.version  = self.request.get('version')
        test_suite.platform  = self.request.get('platform')
        test_suite.download_bandwidth_kbps = int(self.request.get('download_bandwidth_kbps'))
        test_suite.upload_bandwidth_kbps = int(self.request.get('upload_bandwidth_kbps'))
        test_suite.round_trip_time_ms = int(self.request.get('round_trip_time_ms'))
        test_suite.packet_loss_rate  = int(self.request.get('packet_loss_rate'))
        key = test_suite.put()
        self.response.out.write(key)


# Create an entry in the store for a new test run.
class TestResultPage(webapp.RequestHandler):
    def get(self):
        if not users.get_current_user():
            self.redirect(users.create_login_url(self.request.uri))
            return

        recent_suites = models.TestSuite.all().order('-date');
        template_values = { "tests" : recent_suites }
        path = os.path.join(os.path.dirname(__file__), 'create_test_result.html')
        self.response.out.write(template.render(path, template_values))

    def post(self):
        user = users.get_current_user()
        #if not user:
        #    self.redirect(users.create_login_url(self.request.uri))
        #    return

        my_key = self.request.get('test_id')
        my_test = models.TestSuite.get(db.Key(my_key))
        if not my_test:
            self.response.out.write("Could not find test")
            return
        my_url = self.request.get('url');

        test_result = models.TestResult(suite=my_test, url=my_url)
        test_result.using_spdy = bool(self.request.get('using_spdy')=="CHECKED")
        test_result.start_load_time = int(self.request.get('start_load_time'))
        test_result.commit_load_time = int(self.request.get('commit_load_time'))
        test_result.doc_load_time = int(self.request.get('doc_load_time'))
        test_result.paint_time = int(self.request.get('paint_time'))
        test_result.total_time = int(self.request.get('total_time'))
        test_result.num_requests = int(self.request.get('num_requests'))
        test_result.num_connects = int(self.request.get('num_connects'))
        test_result.num_sessions = int(self.request.get('num_sessions'))
        test_result.read_bytes_kb = int(self.request.get('read_bytes_kb'))
        test_result.write_bytes_kb = int(self.request.get('write_bytes_kb'))
        key = test_result.put()
        self.response.out.write(key)

class TestRollupPage(webapp.RequestHandler):
    def get(self):
        if not users.get_current_user():
            self.redirect(users.create_login_url(self.request.uri))
            return

        my_key = self.request.get('id')
        if not my_key:
            self.response.out.write("Could not find test rollup.")
            return

        my_rollup = models.TestRollup.get(db.Key(my_key))
        if not my_rollup:
            self.response.out.write("Could not find test rollup.")
            return

        my_suite = models.TestSuite.get(my_rollup.suite.key())
        if not my_rollup:
            self.response.out.write("Could not find test suite for rollup.")
            return

        test_result_query = models.TestResult.gql("WHERE suite=:1 AND url=:2", my_suite.key(), my_rollup.url)
        test_results = test_result_query.fetch(1000);

        if self.request.get("format") == "json":
           self.response.out.write(serializers.serialize('json', test_results))
           return

        # Do the HTML
        template_values = {"rollup": my_rollup,
                           "test_results": test_results}
        path = os.path.join(os.path.dirname(__file__), 'view_test_rollup.html')
        self.response.out.write(template.render(path, template_values))
        return

    def post(self):
        user = users.get_current_user()
        #if not user:
        #    self.redirect(users.create_login_url(self.request.uri))
        #    return

        my_key = self.request.get('test_id')
        my_test = models.TestSuite.get(db.Key(my_key))
        if not my_test:
            self.response.out.write("Could not find test")
            return
        my_url = self.request.get('url');

        test_rollup = models.TestRollup(suite=my_test, url=my_url)
        test_rollup.download_bandwidth_kbps = my_test.download_bandwidth_kbps
        test_rollup.upload_bandwidth_kbps = my_test.upload_bandwidth_kbps
        test_rollup.round_trip_time_ms = my_test.round_trip_time_ms
        test_rollup.packet_loss_rate  = my_test.packet_loss_rate

        test_rollup.iterations = int(self.request.get('iterations'))
        test_rollup.version = self.request.get('platform')
        test_rollup.platform = self.request.get('version')

        test_rollup.using_spdy = bool(self.request.get('using_spdy')=="CHECKED")
        test_rollup.start_load_time = int(self.request.get('start_load_time'))
        test_rollup.commit_load_time = int(self.request.get('commit_load_time'))
        test_rollup.doc_load_time = int(self.request.get('doc_load_time'))
        test_rollup.paint_time = int(self.request.get('paint_time'))
        test_rollup.total_time = int(self.request.get('total_time'))
        test_rollup.total_time_stddev = float(self.request.get('total_time_stddev'))
        test_rollup.num_requests = int(self.request.get('num_requests'))
        test_rollup.num_connects = int(self.request.get('num_connects'))
        test_rollup.num_sessions = int(self.request.get('num_sessions'))
        test_rollup.read_bytes_kb = int(self.request.get('read_bytes_kb'))
        test_rollup.write_bytes_kb = int(self.request.get('write_bytes_kb'))
        key = test_rollup.put()
        self.response.out.write(key)

class UploadJSON(webapp.RequestHandler):
    def get(self):
        if not users.get_current_user():
            self.redirect(users.create_login_url(self.request.uri))
            return

        path = os.path.join(os.path.dirname(__file__), 'upload_json.html')
        self.response.out.write(template.render(path, None))

application = webapp.WSGIApplication(
                                     [
                                      ('/test_suite', TestSuitePage),
                                      ('/test_result', TestResultPage),
                                      ('/test_rollup', TestRollupPage),
                                      ('/json', JSONDataPage),
                                      ('/upload_json', UploadJSON)
                                     ],
                                     debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()

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

# Applies statistics uploaded via the request to the object.
def ApplyStatisticsData(request, obj):
    obj.using_spdy = bool(request.get('using_spdy')=="CHECKED")
    obj.start_load_time = int(request.get('start_load_time'))
    obj.commit_load_time = int(request.get('commit_load_time'))
    obj.doc_load_time = int(request.get('doc_load_time'))
    obj.paint_time = int(request.get('paint_time'))
    obj.total_time = int(request.get('total_time'))
    obj.num_requests = int(request.get('num_requests'))
    obj.num_connects = int(request.get('num_connects'))
    obj.num_sessions = int(request.get('num_sessions'))
    obj.read_bytes_kb = int(request.get('read_bytes_kb'))
    obj.write_bytes_kb = int(request.get('write_bytes_kb'))

class JSONDataPage(webapp.RequestHandler):
    # Do a search for TestSets
    def do_set_search(self):
        query = models.TestSet.all();
        query.order("-date")

        # Apply filters.
        if self.request.get("rtt_filter"):
            query.filter("round_trip_time_ms =", int(self.request.get("rtt_filter")))
        if self.request.get("download_filter"):
            query.filter("download_bandwidth_kbps =", int(self.request.get("download_filter")))
        if self.request.get("upload_filter"):
            query.filter("upload_bandwidth_kbps =", int(self.request.get("upload_filter")))
        if self.request.get("pkt_loss_rate_filter"):
            query.filter("packet_loss_rate =", int(self.request.get("pkt_loss_rate_filter")))
        if self.request.get("platform_filter"):
            query.filter("platform =", self.request.get("platform_filter"))
        if self.request.get("version_filter"):
            query.filter("version =", self.request.get("version_filter"))
        if self.request.get("set_id"):
            test_set = models.TestSet.get(db.Key(self.request.get("set_id")))
            results = test_set.summaries

        results = query.fetch(250)
        self.response.out.write(json.encode(results))
    
    # Lookup a specific TestSet
    def do_set(self):
        set_id = self.request.get("id")
        if not set_id:
            self.response.out.write("Error")
            return
        test_set = models.TestSet.get(db.Key(set_id))

        # We do manual coalescing of multiple data structures
        # into a single json blob.
        output = "{ \"obj\":" + json.encode(test_set);
        output += ", \"summaries\": ["; 
        first = True
        for summary in test_set.summaries:
            if not first:
              output += ","
            first = False
            output += json.encode(summary)
        output += "] }"
        self.response.out.write(output);

    # Lookup a specific TestSummary
    def do_summary(self):
        set_id = self.request.get("id")
        if not set_id:
            self.response.out.write("Error")
            return
        test_summary = models.TestSummary.get(db.Key(set_id))
        output = "{ \"obj\":" + json.encode(test_summary);
        output += ", \"results\": ["; 

        test_set = models.TestSet.get(test_summary.set.key())
        test_results = test_set.results
        test_results.filter("url =", test_summary.url)

        first = True
        for test_result in test_results:
            if not first:
              output += ","
            first = False
            output += json.encode(test_result)
        output += "] }"
        self.response.out.write(output);

    def get(self):
        if not users.get_current_user():
            self.response.out.write("[{}]")
            return

        resource_type = self.request.get("type")
        if not resource_type:
            self.response.out.write("[{}]")
            return

        # Do a query for the appropriate resource type.
        if resource_type == "summary":
            self.do_summary()
            return
        elif resource_type == "result":
            # TODO(mbelshe): implement me!
            return
        elif resource_type == "set":
            self.do_set()
            return
        elif resource_type == "set_search":
            self.do_set_search()
            return

        self.response.out.write("[{}]")

# Create an entry in the store for a new test.
class UploadTestSet(webapp.RequestHandler):
    def post(self):
        user = users.get_current_user()
        # TODO(mbelshe): the dev server doesn't properly handle logins?
        #if not user:
        #    self.redirect(users.create_login_url(self.request.uri))
        #    return

        cmd = self.request.get("cmd");
        if not cmd:
            self.response.out.write("Error")
            return
   
        if cmd == "create":
            test_set = models.TestSet(user=user)
            test_set.notes = self.request.get('notes')
            test_set.cmdline  = self.request.get('cmdline')
            test_set.version  = self.request.get('version')
            test_set.platform  = self.request.get('platform')
            test_set.download_bandwidth_kbps = int(self.request.get('download_bandwidth_kbps'))
            test_set.upload_bandwidth_kbps = int(self.request.get('upload_bandwidth_kbps'))
            test_set.round_trip_time_ms = int(self.request.get('round_trip_time_ms'))
            test_set.packet_loss_rate  = int(self.request.get('packet_loss_rate'))
            key = test_set.put()
            self.response.out.write(key)

        elif cmd == "update":
            set_id = self.request.get("set_id")
            if not set_id:
                self.response.out.write("Error")
                return
            test_set = models.TestSet.get(db.Key(set_id))
            if not test_set:
                self.response.out.write("Error")
                return
            ApplyStatisticsData(self.request, test_set)
            test_set.iterations = int(self.request.get('iterations'))
            test_set.url_count = int(self.request.get('url_count'))
            key = test_set.put()
            self.response.out.write(key)

# Create an entry in the store for a new test run.
class UploadTestResult(webapp.RequestHandler):
    def post(self):
        user = users.get_current_user()
        # TODO(mbelshe): the dev server doesn't properly handle logins?
        #if not user:
        #    self.redirect(users.create_login_url(self.request.uri))
        #    return

        set_id = self.request.get('set_id')
        if not set_id:
            self.response.out.write("Missing set_id")
            return
        test_set = models.TestSet.get(db.Key(set_id))
        if not test_set:
            self.response.out.write("Could not find test")
            return
        my_url = self.request.get('url');

        test_result = models.TestResult(set=test_set, url=my_url)
        ApplyStatisticsData(self.request, test_result)
        key = test_result.put()
        self.response.out.write(key)

class UploadTestSummary(webapp.RequestHandler):
    def post(self):
        user = users.get_current_user()
        # TODO(mbelshe): the dev server doesn't properly handle logins?
        #if not user:
        #    self.redirect(users.create_login_url(self.request.uri))
        #    return

        set_id = self.request.get('set_id')
        test_set = models.TestSet.get(db.Key(set_id))
        if not test_set:
            self.response.out.write("Could not find test")
            return
        my_url = self.request.get('url');

        test_summary = models.TestSummary(set=test_set, url=my_url)
        ApplyStatisticsData(self.request, test_summary)
        test_summary.iterations = int(self.request.get('iterations'))
        test_summary.total_time_stddev = float(self.request.get('total_time_stddev'))
        key = test_summary.put()
        self.response.out.write(key)

application = webapp.WSGIApplication(
                                     [
                                      ('/set', UploadTestSet),
                                      ('/result', UploadTestResult),
                                      ('/summary', UploadTestSummary),
                                      ('/json', JSONDataPage),
                                     ],
                                     debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()

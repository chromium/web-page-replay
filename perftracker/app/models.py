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


#
# PerfTracker Model
#

from google.appengine.ext import db

# This is a group of TestResult
class TestSuite(db.Model):
    user = db.UserProperty()
    date = db.DateTimeProperty(auto_now_add=True)
    notes = db.StringProperty(multiline=True)

    version = db.StringProperty(indexed=True)
    platform = db.StringProperty()
    cmdline = db.StringProperty()

    download_bandwidth_kbps = db.IntegerProperty(indexed=True)
    upload_bandwidth_kbps = db.IntegerProperty(indexed=True)
    round_trip_time_ms = db.IntegerProperty(indexed=True)
    packet_loss_rate  = db.IntegerProperty(indexed=True)

class TestResult(db.Model):
    suite = db.ReferenceProperty(TestSuite, required=True, indexed=True)
    url = db.StringProperty(required=True, indexed=True)
    using_spdy = db.BooleanProperty()
    start_load_time = db.IntegerProperty()
    commit_load_time = db.IntegerProperty()
    doc_load_time = db.IntegerProperty()
    paint_time = db.IntegerProperty()
    total_time = db.IntegerProperty()
    num_requests = db.IntegerProperty()
    num_connects = db.IntegerProperty()
    num_sessions = db.IntegerProperty()
    read_bytes_kb = db.IntegerProperty()
    write_bytes_kb = db.IntegerProperty()

# This is the output of a test which we most frequently query.
class TestRollup(db.Model):
    suite = db.ReferenceProperty(TestSuite, required=True, indexed=True, collection_name="rollups")
    date = db.DateTimeProperty(auto_now_add=True)
    url = db.StringProperty(required=True, indexed=True)
    version = db.StringProperty(indexed=True)
    platform = db.StringProperty()
    download_bandwidth_kbps = db.IntegerProperty(indexed=True)
    upload_bandwidth_kbps = db.IntegerProperty(indexed=True)
    round_trip_time_ms = db.IntegerProperty(indexed=True)
    packet_loss_rate  = db.IntegerProperty(indexed=True)
    iterations = db.IntegerProperty()
    using_spdy = db.BooleanProperty()
    start_load_time = db.IntegerProperty()
    commit_load_time = db.IntegerProperty()
    doc_load_time = db.IntegerProperty()
    paint_time = db.IntegerProperty()
    total_time = db.IntegerProperty()
    total_time_stddev = db.FloatProperty()
    num_requests = db.IntegerProperty()
    num_connects = db.IntegerProperty()
    num_sessions = db.IntegerProperty()
    read_bytes_kb = db.IntegerProperty()
    write_bytes_kb = db.IntegerProperty()

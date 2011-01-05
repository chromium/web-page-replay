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

# The location of Chrome to test
chrome_path = "<path to chrome>"

# The location of the recorded replay data
replay_data_archive = "<path to recorded data archive from web-page-replay>"

# The URL of the PerfTracker web application to post results to
benchmark_server = "<url of server, such as 'localhost:8080' or 'foo.com'>"
benchmark_server_url = "http://" + benchmark_server + "/"

# If this script is set, it will be run between each run.
# Use this to grab a fresh copy of the browser, update your sources, or turn
# on/off monitoring systems.
inter_run_cleanup_script = None

#
# The set of configurations to run
#

# The configuration to use in the runner
configurations = {}
configurations["iterations"] = 15;
configurations["networks"] = [
    {   # Fast Network
        "download_bandwidth_kbps": 0,
        "upload_bandwidth_kbps"  : 0,
    },
    {   # 10Mbps Network
        "download_bandwidth_kbps": 10000,
        "upload_bandwidth_kbps"  : 10000,
    },
    {   # Cable Network
        "download_bandwidth_kbps": 5000,
        "upload_bandwidth_kbps"  : 1000,
    },
    {   # DSL Network
        "download_bandwidth_kbps": 2000,
        "upload_bandwidth_kbps"  : 400,
    }
]
configurations["round_trip_times"] = [
    0, 40, 80, 100, 120, 160, 200
]
configurations["packet_loss_rates"] = [
    0, 1
]

# The list of URLs to test
configurations["urls"] = [
    "http://www.google.com/",
    "<add your list of urls here>
]

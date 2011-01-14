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
#chrome_path = "/usr/local/google/dailychrome/chrome-linux/chrome"
chrome_path = "/usr/local/google/mbelshe/src/out/Release/chrome"

# The location of the recorded replay data
replay_data_archive = "../../data/alexa-top25_20110105.archive"

# The URL of the PerfTracker web application to post results to
#benchmark_server = "perftracker.googleplex.com"
#benchmark_server = "2.latest.perftracker.googleplex.com"
benchmark_hostname = "mbelshe"
benchmark_port = "8080"
benchmark_server = benchmark_hostname + ":" + benchmark_port
benchmark_server_url = "http://" + benchmark_server + "/"

# SPDY options
spdy = {}
spdy['ssl'] = True
spdy['certfile'] = "../cert.pem"
spdy['keyfile'] = "../key.pem"

# If this script is set, it will be run between each run.
# Use this to grab a fresh copy of the browser, update your sources, or turn
# on/off monitoring systems.
inter_run_cleanup_script = None

#
# The set of configurations to run
#

# The configuration to use in the runner
configurations = {}
configurations["iterations"] = 3;
configurations["networks"] = [
#    {   # Fast Network
#        "download_bandwidth_kbps": 0,
#        "upload_bandwidth_kbps"  : 0,
#    },
    {   # 10Mbps Network
        "download_bandwidth_kbps": 10000,
        "upload_bandwidth_kbps"  : 10000,
    },
    {   # Cable Network
        "download_bandwidth_kbps": 5000,
        "upload_bandwidth_kbps"  : 1000,
    },
#    {   # DSL Network
#        "download_bandwidth_kbps": 2000,
#        "upload_bandwidth_kbps"  : 400,
#    }
]

configurations["round_trip_times"] = [
#    0, 40, 80, 100, 120, 160, 200
    0, 10, 20, 30
]

configurations["packet_loss_rates"] = [
#    0, 1
    0
]

configurations["protocols"] = [
    "http",
    "spdy",
]

# The list of URLs to test
configurations["urls"] = [
    "http://www.google.com/",
    "http://www.google.com/search?q=dogs",
    "http://www.facebook.com/",
]

configurations["urls2"] = [
    "http://www.google.com/",
    "http://www.google.com/search?q=dogs",
    "http://www.facebook.com/",
    "http://www.youtube.com/",
    "http://www.yahoo.com/",
    "http://www.baidu.com/",
    "http://www.baidu.com/s?wd=obama",
    "http://www.wikipedia.org/",
    "http://en.wikipedia.org/wiki/Lady_gaga",
    "http://googleblog.blogspot.com/",
    "http://www.qq.com/",
    "http://twitter.com/",
    "http://twitter.com/search?q=pizza",
    "http://www.msn.com/",
    "http://www.yahoo.co.jp/",
# this one has a hardcoded IP to 110.75.1.110.
#    "http://www.taobao.com/index_global.php",
    "http://www.amazon.com/",
    "http://wordpress.com/",
    "http://www.linkedin.com/",
    "http://www.microsoft.com/en/us/default.aspx",
    "http://www.ebay.com/",
    "http://fashion.ebay.com/womens-clothing",
    "http://www.bing.com/",
    "http://www.bing.com/search?q=cars",
    "http://www.yandex.ru/",
    "http://yandex.ru/yandsearch?text=obama&lr=84",
    "http://www.163.com/",
    "http://www.fc2.com/",
    "http://www.conduit.com/",
    "http://www.mail.ru/",
    "http://www.flickr.com/",
    "http://www.flickr.com/photos/tags/flowers",
    "http://www.nytimes.com/",
    "http://www.cnn.com/",
    "http://www.apple.com/",
    "http://www.bbc.co.uk/"
]

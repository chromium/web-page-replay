// Copyright 2010 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


// The port for communicating back to the extension.
var benchmarkExtensionPort = chrome.extension.connect();

// The url is what this page is known to the benchmark as.
// The benchmark uses this id to differentiate the benchmark's
// results from random pages being browsed.

// TODO(mbelshe): If the page redirects, the location changed and the
// benchmark stalls.
var benchmarkExtensionUrl = window.location.toString();
var kTCPReadBytes = "tcp.read_bytes";
var bytes_read = chrome.benchmarking.counter(kTCPReadBytes);
var heartbeat_count = 0;

console.log("script injected into: " + window.location.toString())

function sendTimesToExtension() {
  console.log("checking for page done");
  if (window.parent != window) {
    console.log("not my page.");
    return;
  }
  var load_times = window.chrome.loadTimes();

  var new_bytes_read = chrome.benchmarking.counter(kTCPReadBytes);

  // If the load is not finished yet, schedule a timer to check again in a
  // little bit.
  if (load_times.finishLoadTime != 0) {
    // If the network is still reading bytes, let it acquiesce
    if (bytes_read == new_bytes_read) {
      benchmarkExtensionPort.postMessage({message: 'load',
                                          url: benchmarkExtensionUrl,
                                          values: load_times });
      console.log("page finished")
      return;
    }
    console.log("page still changing")
  }

  // We're still waiting.  Check again in a little bit.
  bytes_read = new_bytes_read;
  var id = window.setTimeout(sendTimesToExtension, 200);
  console.log("will try again in 500ms. timer is: " + id)

  // Send a heartbeat to the extension.
  benchmarkExtensionPort.postMessage({message: 'heartbeat',
                                      count: heartbeat_count});
  heartbeat_count++;
}

// We can't use the onload event because this script runs at document idle,
// which may run after the onload has completed.
sendTimesToExtension();

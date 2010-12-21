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

// TODO(mbelshe): Remove all these console.log statements

// The url is what this page is known to the benchmark as.
// The benchmark uses this id to differentiate the benchmark's
// results from random pages being browsed.
// TODO(mbelshe): If the page redirects, the location changed and the
// benchmark stalls.
var benchmarkExtensionUrl = window.location.toString();
var heartbeatCount = 0;
var heartbeatInterval = 1000;

var scheduleCheckForLoadFinished = function() {
  setTimeout(checkForLoadFinished, heartbeatInterval);
};

var checkForLoadFinished = function() {
  console.log("script checkForLastLoad: " + heartbeatCount);

  var benchmarkExtensionPort = chrome.extension.connect();
  var loadTimes = chrome.loadTimes();
  var timing = webkitPerformance.timing;

  if (!loadTimes.finishLoadTime || !timing.loadEventStart) {
    benchmarkExtensionPort.postMessage({message: 'heartbeat',
		                        count: heartbeatCount});
    heartbeatCount++;
    scheduleCheckForLoadFinished();
  } else {
    console.log("checkForLastLoad finished!");
    // TODO(tonyg): For diagnostics, this currently ignores LLT and just uses PLT.
    loadTimes.lastLoadTime = timing.loadEventStart - timing.navigationStart;
    benchmarkExtensionPort.postMessage({message: 'load',
                                        url: benchmarkExtensionUrl,
                                        values: loadTimes });
  }
};

var registerListeners = function() {
  if (window.parent != window) {
    console.log("not my page.");
    return;
  }
  console.log("registerListeners");
  scheduleCheckForLoadFinished();
};

registerListeners();

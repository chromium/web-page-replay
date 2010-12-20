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
var heartbeatInterval = 1000;  // TODO: Make this a function of window load time
var lastLoadTime = 0;
var previousLoadTime = 0;

var checkForLastLoad = function() {
  console.log("script checkForLastLoad");
  var loadTimes = chrome.loadTimes();
  var timing = webkitPerformance.timing;
  var benchmarkExtensionPort = chrome.extension.connect();
  if (/*lastLoadTime > previousLoadTime ||*/ !loadTimes.finishLoadTime || !timing.loadEventStart) {
    console.log("checkForLastLoad posting heartbeat");
    previousLoadTime = lastLoadTime;
    benchmarkExtensionPort.postMessage({message: 'heartbeat',
                                        count: heartbeatCount});
    heartbeatCount++;
    setTimeout(checkForLastLoad, heartbeatInterval);
  } else {
    console.log("checkForLastLoad finished!");
    // TODO(tonyg): For diagnostics, this currently ignores LLT and just uses PLT.
    loadTimes.lastLoadTime = timing.loadEventStart - timing.navigationStart;
    benchmarkExtensionPort.postMessage({message: 'load',
                                        url: benchmarkExtensionUrl,
                                        values: loadTimes });
  }
};

var onWindowFinished = function(e) {
  lastLoadTime = webkitPerformance.timing.loadEventStart;
  console.log("Window finished at " + lastLoadTime);
  checkForLastLoad();
};

var onElementFinished = function(e) {
  lastLoadTime = new Date();
  console.log("Element finished at " + lastLoadTime);
};

var registerListeners = function() {
  if (window.parent != window) {
    console.log("not my page.");
    return;
  }

  console.log("registerListeners");

  if (document.readyState == "complete") {
    // The load event may have already fired.
    onWindowFinished();
  } else {
    // Called when the window loads.
    window.addEventListener('load', onWindowFinished, true);
    window.addEventListener('error', onWindowFinished, true);
    window.addEventListener('abort', onWindowFinished, true);

    // Called each time a subresource finishes.
    //document.addEventListener('load', onElementFinished, true);
    //document.addEventListener('error', onElementFinished, true);
    //document.addEventListener('abort', onElementFinished, true);
  }
};

registerListeners();

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
var windowLoad = 0;
var lastElementLoad = 0;
var latestLoad = 0;

var checkForLastLoad = function() {
  console.log("script checkForLastLoad");
  var benchmarkExtensionPort = chrome.extension.connect();
  var loadTimes = chrome.loadTimes();
  if (lastElementLoad > latestLoad || !loadTimes.finishLoadTime) {
    console.log("checkForLastLoad posting heartbeat");
    latestLoad = lastElementLoad;
    benchmarkExtensionPort.postMessage({message: 'heartbeat',
                                        count: heartbeatCount});
    heartbeatCount++;
    setTimeout(checkForLastLoad, heartbeatInterval);
  } else {
    console.log("checkForLastLoad finished!");
    loadTimes.lastLoadTime = latestLoad / 1000.0;
    benchmarkExtensionPort.postMessage({message: 'load',
                                        url: benchmarkExtensionUrl,
                                        values: loadTimes });
  }
};

var onWindowFinished = function(e) {
  windowLoad = new Date();
  latestLoad = windowLoad;
  console.log("Window finished at " + windowLoad);
};

var onElementFinished = function(e) {
  lastElementLoad = new Date();
  console.log("Element finished at " + lastElementLoad);
};

var registerListeners = function() {
  if (window.parent != window) {
    console.log("not my page.");
    return;
  }
  
  // Called when the window loads.
  window.addEventListener('load', onWindowFinished, true);

  // Called each time a subresource loads.
  document.addEventListener('load', onElementFinished, true);
  document.addEventListener('error', onElementFinished, true);

  // When injecting into someone else's page, we don't always get the
  // onWindowFinished event.  Resort to polling.
  checkForLastLoad();
  console.log("script register complete");
};

registerListeners();

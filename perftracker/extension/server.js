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

// Functions for uploading to the server

// These are the URLs used by the backend for posting data
var kServerPostSuiteUrl = "test_suite";
var kServerPostResultUrl = "test_result";
var kServerPostRollupUrl = "test_rollup";

// BrowserDetect is thanks to www.quirksmode.org/js/detect.html
var BrowserDetect = {
  init: function () {
    this.browser = this.searchString(this.dataBrowser) || "An unknown browser";
    this.version = this.searchVersion(navigator.userAgent)
      || this.searchVersion(navigator.appVersion)
      || "an unknown version";
    this.OS = this.searchString(this.dataOS) || "an unknown OS";
  },
  searchString: function (data) {
    for (var i=0;i<data.length;i++)  {
      var dataString = data[i].string;
      var dataProp = data[i].prop;
      this.versionSearchString = data[i].versionSearch || data[i].identity;
      if (dataString) {
        if (dataString.indexOf(data[i].subString) != -1)
          return data[i].identity;
      }
      else if (dataProp)
        return data[i].identity;
    }
  },
  searchVersion: function (dataString) {
    var index = dataString.indexOf(this.versionSearchString);
    if (index == -1)
      return;
    var version_string = dataString.substring(index+this.versionSearchString.length+1);
    var end_index = version_string.indexOf(" ");
    if (end_index < 0) {
      return version_string;
    }
    return version_string.substring(0, end_index);
  },
  dataBrowser: [
    {
      string: navigator.userAgent,
      subString: "Chrome",
      identity: "Chrome"
    },
    {
      string: navigator.vendor,
      subString: "Apple",
      identity: "Safari",
      versionSearch: "Version"
    },
    {
      prop: window.opera,
      identity: "Opera"
    },
    {
      string: navigator.userAgent,
      subString: "Firefox",
      identity: "Firefox"
    },
    {    // for newer Netscapes (6+)
      string: navigator.userAgent,
      subString: "Netscape",
      identity: "Netscape"
    },
    {
      string: navigator.userAgent,
      subString: "MSIE",
      identity: "Explorer",
      versionSearch: "MSIE"
    },
    {
      string: navigator.userAgent,
      subString: "Gecko",
      identity: "Mozilla",
      versionSearch: "rv"
    },
  ],
  dataOS : [
    {
      string: navigator.platform,
      subString: "Win",
      identity: "Windows"
    },
    {
      string: navigator.platform,
      subString: "Mac",
      identity: "Mac"
    },
    {
      string: navigator.userAgent,
      subString: "iPhone",
      identity: "iPhone/iPod"
    },
    {
      string: navigator.platform,
      subString: "Linux",
      identity: "Linux"
    }
  ]
};
BrowserDetect.init();

Array.max = function(array) {
  return Math.max.apply( Math, array );
}

Array.min = function(array) {
  return Math.min.apply( Math, array );
};

// Compute the average of an array, removing the min/max.
Array.avg = function(array) {
  var count = array.length;
  var sum = 0;
  var min = array[0];
  var max = array[0];
  for (var i = 0; i < count; i++) {
    sum += array[i];
    if (array[i] < min) {
      min = array[i];
    }
    if (array[i] > max) {
      max = array[i];
    }
  }
  if (count >= 3) {
    sum = sum - min - max;
    count -= 2;
  }
  return sum / count;
}

// Compute the standard deviation of an array
// TODO(mbelshe):  Note that the Array.avg() removes the min/max elts.
//                 But this function does not.... it should!
Array.stddev = function(array) {
  var count = array.length;
  var mean = Array.avg(array);
  var variance = 0;
  for (var i = 0; i < count; i++) {
    var deviation = mean - array[i];
    variance = variance + deviation * deviation;
  }
  variance = variance / count;
  return Math.sqrt(variance);
}

function XHRGet(url, callback) {
  var self = this;
  var xhr = new XMLHttpRequest();
  xhr.open("GET", url, true);
  xhr.send();

  xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
      callback(xhr.responseText);
    }
  }
}

function XHRPost(url, data, callback) {
  var self = this;
  var xhr = new XMLHttpRequest();
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  xhr.send(data);

  xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
      callback(xhr.responseText);
    }
  }
}

// Submits a set of test runs up to the server.
function TestResultSubmitter(config) {
  var self = this;
  var test_id;
  var create_test_started = false;
  var user_callback;

  this.AppEngineLogin = function(callback) {
    new XHRGet(config.server_login, function() {
      callback();
    });
  }
  
  // Creates the test.  This should only be called once.
  // Upon test creation, the callback will be called with a single argument
  // containing the status of the creation.
  this.CreateTest = function(callback) {
    if (create_test_started) {
      callback(test_id);
      return;
    }

    self.AppEngineLogin(function() {
      create_test_started = true;
      var data = "";
      data += "download_bandwidth_kbps=" + config.download_bandwidth_kbps;
      data += "&upload_bandwidth_kbps=" + config.upload_bandwidth_kbps;
      data += "&round_trip_time_ms=" + config.round_trip_time_ms;
      data += "&packet_loss_rate=" + config.packet_loss_rate;
      data += "&notes=" + config.notes;
      data += "&version=" + BrowserDetect.browser + " " + BrowserDetect.version;
      data += "&platform=" + BrowserDetect.OS;
      data += "&cmdline=" + config.cmdline;

      url = config.server_url + kServerPostSuiteUrl

      user_callback = callback;
      new XHRPost(url, data, function(result) {
        test_id = result;
        user_callback(result);
      });
    });
  }

  // Post a single result
  this.PostResult = function (result, callback) {
    var data = "";
    data += "test_id=" + test_id;
    data += "&url=" + result.url;
    data += "&using_spdy=" + (result.viaSpdy ? "CHECKED" : "");
    data += "&start_load_time=" + result.startLoadTime;
    data += "&commit_load_time=" + result.commitLoadTime;
    data += "&doc_load_time=" + result.docLoadTime;
    data += "&paint_time=" + result.paintTime;
    data += "&total_time=" + result.totalTime;
    data += "&num_requests=" + result.requests;
    data += "&num_connects=" + result.connects;
    data += "&num_sessions=" + result.spdySessions;
    data += "&read_bytes_kb=" + Math.floor(result.readKB);
    data += "&write_bytes_kb=" + Math.floor(result.writeKB);

    url = config.server_url + kServerPostResultUrl;
    user_callback = callback;
    new XHRPost(url, data, function(result) { user_callback(result); });
  }

  // Post the rollup of a set of data
  this.PostRollup = function(data, callback) {
    var result = {};
    result.iterations = data.totalResults.length;
    result.url = data.url;
    result.using_spdy = data.using_spdy;

    result.using_spdy = data.using_spdy;
    result.start_load_time = Array.avg(data.startLoadResults);
    result.commit_load_time = Array.avg(data.commitLoadResults);
    result.doc_load_time = Array.avg(data.docLoadResults);
    result.paint_time = Array.avg(data.paintResults);
    result.total_time = Array.avg(data.totalResults);
    result.total_time_stddev = Array.stddev(data.totalResults);
    result.connects = Array.avg(data.connects);
    result.sessions = Array.avg(data.spdySessions);
    result.requests = Array.avg(data.requests);
    result.readKB = Array.avg(data.KbytesRead);
    result.writeKB = Array.avg(data.KbytesWritten);

    var data = "";
    data += "test_id=" + test_id;

    data += "&download_bandwidth_kbps=" + config.download_bandwidth_kbps;
    data += "&upload_bandwidth_kbps=" + config.upload_bandwidth_kbps;
    data += "&round_trip_time_ms=" + config.round_trip_time_ms;
    data += "&packet_loss_rate=" + config.packet_loss_rate;
    data += "&version=" + BrowserDetect.browser + " " + BrowserDetect.version;
    data += "&platform=" + BrowserDetect.OS;

    data += "&url=" + result.url;
    data += "&iterations=" + result.iterations;
    data += "&using_spdy=" + (result.viaSpdy ? "CHECKED" : "");
    data += "&start_load_time=" + Math.floor(result.start_load_time);
    data += "&commit_load_time=" + Math.floor(result.commit_load_time);
    data += "&doc_load_time=" + Math.floor(result.doc_load_time);
    data += "&paint_time=" + Math.floor(result.paint_time);
    data += "&total_time=" + Math.floor(result.total_time);
    data += "&total_time_stddev=" + result.total_time_stddev;
    data += "&num_connects=" + Math.floor(result.connects);
    data += "&num_sessions=" + Math.floor(result.sessions);
    data += "&num_requests=" + Math.floor(result.requests);
    data += "&read_bytes_kb=" + Math.floor(result.readKB);
    data += "&write_bytes_kb=" + Math.floor(result.writeKB);

    console.log("DATA ROLLUP IS: " + data);

    url = config.server_url + kServerPostRollupUrl;
    user_callback = callback;
    new XHRPost(url, data, function(result) { user_callback(result); });
  }
}

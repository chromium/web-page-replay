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
var kServerPostSetUrl = "set";
var kServerPostResultUrl = "result";
var kServerPostSummaryUrl = "summary";

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

// Returns the max value in the array.
Array.max = function(array) {
  return Math.max.apply(Math, array);
};

// Returns the min value in the array.
Array.min = function(array) {
  return Math.min.apply(Math, array);
};

// Returns the sum of all values in the array.
Array.sum = function(array) {
  var sum = 0;
  for (var i = array.length - 1; i >= 0; i--) {
    sum += array[i];
  }
  return sum;
};

// Returns the average value of the array, excluding the min and max values.
Array.trimmedMean = function(array) {
  var count = array.length;
  if (count == 0) {
    return 0;
  }

  var sum = Array.sum(array);
  if (count > 2) {
    sum -= Array.min(array) + Array.max(array);
    count -= 2;
  }
  return Math.round(sum / count);
}

// Returns the standard deviation of the array, excluding the min and max values.
Array.trimmedStdDev = function(array) {
  var count = array.length;
  if (count == 0) {
    return 0;
  }
  var trimmedMean = Array.trimmedMean(array);
  var min = Array.min(array);
  var max = Array.max(array);
  var variance = 0;
  for (var i = 0; i < count; i++) {
    if (count > 2 && (array[i] == min || array[i] == max)) continue;
    var deviation = trimmedMean - array[i];
    variance += deviation * deviation;
  }
  if (count > 2) count -= 2;
  variance /= count;
  return Math.sqrt(variance);
}

function XHRGet(url, callback) {
  var self = this;
  var xhr = new XMLHttpRequest();
  xhr.open("GET", url, true);
  xhr.send();

  xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
      if (xhr.status != 200)  {
        console.log("XHR error getting url " + url + ", error: " + xhr.status);
      }
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
      if (xhr.status != 200)  {
        console.log("XHR error posting url " + url + ", error: " + xhr.status);
      }
      callback(xhr.responseText);
    }
  }
}

function copy(obj) {
  var copy = {};
  for (var prop in obj)
    copy[prop] = obj[prop];
  return copy;
}

function jsonToPostData(json) {
  var post_data = [];
  for (var prop in json) {
    post_data.push(prop + "=" + encodeURIComponent(json[prop]));
  }
  return post_data.join("&");
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
      if (config.record) { setTimeout(callback, 0); return; }
      create_test_started = true;
      var data = copy(config);
      data["cmd"] = "create";
      data["version"] = BrowserDetect.browser + " " + BrowserDetect.version;
      data["platform"] = BrowserDetect.OS;

      url = config.server_url + kServerPostSetUrl;

      // When special notes are added, we consider the result a custom version.
      if (config.notes.length > 0) {
        data["version"] += "custom" + config.notes;
      }

      user_callback = callback;
      new XHRPost(url, jsonToPostData(data), function(result) {
        test_id = result;
        user_callback(result);
      });
    });
  }

  // Post a single result
  this.PostResult = function (result, callback) {
    if (config.record) { setTimeout(callback, 0); return; }
    var data = copy(result);
    data["set_id"] = test_id;

    url = config.server_url + kServerPostResultUrl;
    user_callback = callback;
    new XHRPost(url, jsonToPostData(data),
		function(result) { user_callback(result); });
  }

  // Post the rollup summary of a set of data
  this.PostSummary = function(data, callback) {
    if (config.record) { setTimeout(callback, 0); return; }
    var result = copy(data);
    // Average everything except the special properties.
    for (var prop in result) {
      if (prop == "url" || prop == "using_spdy" || prop == "iterations")
	continue;
      result[prop] = Array.trimmedMean(result[prop]);
    }
    result["set_id"] = test_id;
    result["total_time_stddev"] = Array.trimmedStdDev(data.total_time);

    url = config.server_url + kServerPostSummaryUrl;
    user_callback = callback;
    new XHRPost(url, jsonToPostData(result),
		function(result) { user_callback(result); });
  }

  // Update the set with its summary data
  this.UpdateSetSummary = function(data, callback) {
    if (config.record) { setTimeout(callback, 0); return; }
    var result = copy(data);
    // Divide everything by iterations except the special properties.
    for (var prop in result) {
      if (prop == "iterations") {
	result.iterations = Math.round(data.iterations / data.url_count);
	continue;
      }
      if (prop == "url_count")
	continue;
      result[prop] = Math.round(result[prop] / data.iterations);
    }
    result["cmd"] = "update";
    result["set_id"] = test_id;

    url = config.server_url + kServerPostSetUrl;
    user_callback = callback;
    new XHRPost(url, jsonToPostData(result),
		function(result) { user_callback(result); });
  }

}

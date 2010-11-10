Object.prototype.keys = function() {
  var keys = [];
  for (key in this) {
    if (this.hasOwnProperty(key)) {
      keys.push(key);
    }
  }
  return keys;
}

Array.prototype.contains = function(obj) {
  var i = this.length;
  while (i--) {
    if (this[i] == obj) {
      return true;
    }
  }
  return false;
}

Array.prototype.push_unique = function(obj) {
  if (!this.contains(obj)) {
    this.push(obj);
    return true;
  }
  return false;
}

window.location.queryString = function() {
  var result = {};
  var raw_string = decodeURI(location.search);
 
  if (!raw_string || raw_string.length == 0) {
    return result;
  }

  raw_string = raw_string.substring(1);  // trim leading '?'
  
  var name_values = raw_string.split("&");
  for (var i = 0; i < name_values.length; ++i) {
    var elts = name_values[i].split('=');
    result[elts[0]] = elts[1];
  }

  return result;
};

// Wrapper around XHR.
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

// Given a stddev and a sample count, compute the stderr
function stderr(stddev, sample_count) {
  return stddev / Math.sqrt(sample_count);
}

// Given a stderr, compute the confidence interval
function ci(stderr) {
  return 1.96 * stderr;
}


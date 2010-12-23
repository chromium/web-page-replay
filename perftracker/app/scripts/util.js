Array.prototype.contains = function(obj) {
  var i = this.length;
  while (i--) {
    if (this[i] == obj) {
      return true;
    }
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
function XHRGet(url, callback, data) {
  var self = this;
  var xhr = new XMLHttpRequest();
  xhr.open("GET", url, true);
  xhr.send();

  xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
      if (xhr.status != 200) {
        alert("Error: could not download (" + url + "): " + xhr.status);
      }
      callback(xhr.responseText, data);
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

// Sets the selected option of the <select> with id=|id|.
function setSelectValue(id, value) {
    if (!id || !value) return;
    var elt = document.getElementById(id);
    for (var i = 0; i < elt.options.length; i++) {
        if (elt.options[i].text == value)
          elt.options[i].selected = true
	  else
	      elt.options[i].selected = false;
    }
}

// Gets the value of the selected option of the <select> with id=|id|.
function getSelectValue(id) {
    var elt = document.getElementById(id);
    return elt[elt.selectedIndex].value;
}

// Sets the parameters in the URL fragment to those in the |newParams| key:value map.
function setParams(params) {
    var hashString = "";
    for (var param in params) {
      if (!param) continue;
      hashString += "&" + param + "=" + encodeURIComponent(params[param]);
    }
    window.location.hash = "#" + hashString.substring(1);
}

// Returns a key:value map of all parameters in the URL fragment.
function getParams() {
    var map = {};
    var hash = window.location.hash.substring(1);
    pairs = hash.split("&");
    for (var i = 0; i < pairs.length; i++) {
        var key_val = pairs[i].split("=");
        map[key_val[0]] = decodeURIComponent(key_val[1]);
    }
    return map;
}

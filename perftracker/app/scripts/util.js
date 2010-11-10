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

// Round a number to the 1's place.
function formatNumber(str) {
  str += '';
  if (str == '0') {
    return 'N/A ';
  }
  var x = str.split('.');
  var x1 = x[0];
  var x2 = x.length > 1 ? '.' + x[1] : '';
  var regex = /(\d+)(\d{3})/;
  while (regex.test(x1)) {
    x1 = x1.replace(regex, '$1' + ',' + '$2');
  }
  return x1;
}

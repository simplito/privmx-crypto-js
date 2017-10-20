function Event() {
  this.callbacks = [];
}

Event.prototype.add = function(callback) {
  this.callbacks.push(callback);
}

Event.prototype.remove = function(callback) {
  for (var i = 0; i < this.callbacks.length; i++) {
    if (this.callbacks[i] == callback) {
      this.callbacks.splice(i, 1);
      return;
    }
  }
}

Event.prototype.clear = function() {
  this.callbacks = [];
}

Event.prototype.trigger = function() {
  if (this.callbacks.length == 0) {
      return;
  }
  var args = arguments;
  setTimeout(function(){
    this.callbacks.forEach(function(callback) {
      callback.apply(null, args);
    });
  }.bind(this), 1);
}

module.exports = Event;

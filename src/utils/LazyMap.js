function LazyMap(valueGetter) {
    this.valueGetter = valueGetter;
}

LazyMap.prototype.get = function(key) {
    if (key in this) {
        return this[key];
    }
    if (this.valueGetter != null) {
        var value = this.valueGetter(this, key);
        if (typeof(value) != "undefined") {
            this[key] = value;
            return this[key];
        }
    }
    throw new Error("Value under key '" + key + "' cannot be resolved");
}

module.exports = LazyMap;
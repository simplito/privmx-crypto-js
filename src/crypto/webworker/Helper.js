function Helper() {
    
}

Helper.prototype.getTransferable = function(obj) {
    if (obj instanceof ArrayBuffer) {
        return [obj];
    }
    var result = [];
    if (Array.isArray(obj)) {
        for (var i = 0; i < obj.length; i++) {
            if (obj[i] instanceof ArrayBuffer) {
                result.push(obj[i]);
            }
        }
    }
    else if (typeof(obj) == "object") {
        for (var name in obj) {
            if (obj[name] instanceof ArrayBuffer) {
                result.push(obj[name]);
            }
        }
    }
    return result;
}

module.exports = new Helper();
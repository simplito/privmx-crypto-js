var Service = require("../Service");
var Serializer = require("./Serializer");
var Helper = require("./Helper");
var Q = require("q");

var isWorker = function() { try { return (typeof self.document == "undefined"); } catch(e) { return false; } }

function Listener() {
    onmessage = this.onMessage.bind(this);
}

Listener.prototype.onMessage = function(event) {
    var method = event.data.method;
    if (method == "randomFeed") {
        Service.randomFeed(Serializer.decode(event.data.params[0]));
        return;
    }
    Q().then(() => {
        var params = Serializer.decode(event.data.params);
        return Service.execute(method, params);
    })
    .then((result) => {
        result = Serializer.encode(result);

        postMessage({
            id: event.data.id,
            result: result
        }, Helper.getTransferable(result));
    })
    .catch((e) => {
        postMessage({
            id: event.data.id,
            error: e.toString()
        });
    });
}

if (isWorker()) {
    module.exports = new Listener();
}
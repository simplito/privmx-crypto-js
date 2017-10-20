var Serializer = require("./Serializer");
var Helper = require("./Helper");
var Q = require("q");

/**
 * Requester
 * @class
 * @param {string} path
 */
function Requester(path) {
    this.tasks = {};
    this.taskId = 0;
    try {
        this.worker = new Worker(path);
        this.worker.onmessage = this.onMessage.bind(this);
        this.worker.onerror = () => this.isSupported = () => false;
        // Feed worker with 256 bytes of initial entropy
        this.service = require("../Service");
        var params = Serializer.encode([this.service.randomBytes(256)]);
        this.worker.postMessage({id:0, method: "randomFeed", params: params});
    } catch (error) {
        console.log("Requester error", error);
        this.isSupported = () => false;
    }
}

Requester.prototype = Object.create(Requester.prototype);
Requester.prototype.constructor = Requester;

/**
 * On worker response
 * @params {object} event
 */
Requester.prototype.onMessage = function(event) {
    var task = this.tasks[event.data.id];
    if (task == null) {
        throw new Error("Invalid task id");
    }
    delete this.tasks[event.data.id];
    if ("result" in event.data) {
        task.resolve(event.data.result);
    }
    else {
        task.reject(event.data.error);
    }
}

/**
 * Execute given method with given parameters
 * @param {string} method
 * @param {List[any]} params
 * @return {Promise[any]}
 */
Requester.prototype.execute = function(method, params) {
    return Q().then(() => {
        var defered = Q.defer();
        this.taskId++;
        this.tasks[this.taskId] = defered;
        params = Serializer.encode(params);

        this.worker.postMessage({
            id: this.taskId,
            method: method,
            params: params
        }, Helper.getTransferable(params));

        return defered.promise;
    }).then((result) => {
        return Serializer.decode(result);
    });
}

module.exports = Requester;
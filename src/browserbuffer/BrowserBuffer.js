
function BrowserBuffer() {
}

/**
 * Converts Buffer to ArrayBuffer
 * @param {Buffer} buffer
 * @param {boolean} copy - default: true, if true returns copy of ArrayBuffer
 * @return {ArrayBuffer}
 */
BrowserBuffer.prototype.bufferToArray = function(buffer, copy) {
    if (copy === void 0) { copy = true; }
    // if (buffer.buffer && (buffer.buffer instanceof ArrayBuffer)) {
    //     if (copy) {
    //         return buffer.buffer.slice(0);
    //     }

    //     return buffer.buffer;
    // }
    if (typeof(buffer.toArrayBuffer) == "function") {
        return buffer.toArrayBuffer();
    }
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return ab;
}

/**
 * Converts ArrayBuffer to Buffer
 * @param {ArrayBuffer} ab
 * @return {Buffer}
 */
BrowserBuffer.prototype.arrayToBuffer = function(ab) {
    return Buffer.from(ab).slice(0)
}

/**
 * Checks whether the arg is a Buffer
 * @param  {*} arg
 * @return {boolean}
 */
BrowserBuffer.prototype.isBuffer = function(arg) {
    return Buffer.isBuffer(arg) || arg instanceof Uint8Array;
}

/**
 * Create blob from buffer and mimetype
 * @param  {Buffer} buffer
 * @param  {string} mimetype
 * @return {Blob}
 */
BrowserBuffer.prototype.createBlob = function(buffer, mimetype) {
  return new Blob([this.bufferToArray(buffer)], {type: mimetype});
};

module.exports = new BrowserBuffer();

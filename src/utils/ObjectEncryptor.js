var BrowserBuffer = require("../browserbuffer/BrowserBuffer");
var CryptoService = require("../crypto/Service");

/**
 * ObjectEncryptor
 * @class
 * @param {Buffer} key
 * @param {EncryptOptions} encryptOptions (optional, default AES-256-CBC with HMAC and attached IV)
 * @param {DecryptOptions} decryptOptions (optional, default empty)
 */
function ObjectEncryptor(key, encryptOptions, decryptOptions) {
    if (!BrowserBuffer.isBuffer(key) || key.length != 32) {
        throw new Error("Invalid argument: key - expected Buffer 32 bytes long");
    }
    Object.defineProperty(this, "key", {value: key, enumerable: true});
    this.encryptOptions = encryptOptions || CryptoService.privmxOptAesWithSignature();
    this.decryptOptions = decryptOptions || CryptoService.privmxOptSignedCipher();
}

/**
 * Encrypt object
 * @param {object} object
 * @return {Promise[Buffer]}
 */
ObjectEncryptor.prototype.encrypt = function(object) {
    var buff = new Buffer(JSON.stringify(object), "utf8");
    return CryptoService.privmxEncrypt(this.encryptOptions, buff, this.key);
};

/**
 * Decrypt object
 * @param {Buffer} encrypted
 * @return {Promise[Object]}
 */
ObjectEncryptor.prototype.decrypt = function(encrypted) {
    return CryptoService.privmxDecrypt(this.decryptOptions, encrypted, this.key).then(function(buff) {
        return JSON.parse(buff.toString("utf8"));
    });
};

module.exports = ObjectEncryptor;
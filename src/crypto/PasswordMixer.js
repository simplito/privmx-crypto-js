var Q = require("q");
var CryptoService = require("./Service");

function PasswordMixer() {
}

/**
 * Serialize data
 * @param {object} data
 * @return {string}
 */
PasswordMixer.prototype.serializeData = function(data) {
    return JSON.stringify({
        algorithm: data.algorithm,
        hash: data.hash,
        length: data.length,
        rounds: data.rounds,
        salt: data.salt.toString("base64"),
        version: data.version
    });
}

/**
 * Deserialize data
 * @param {string} raw
 * @return {object}
 */
PasswordMixer.prototype.deserializeData = function(raw) {
    var data = JSON.parse(raw);
    data.salt = new Buffer(data.salt, "base64")
    return data;
}

/**
 * Generate pbkdf2 mixed password
 * @param {string} password
 * @return {Promise[object]}
 */
PasswordMixer.prototype.generatePbkdf2 = function(password) {
    var data = {
        algorithm: "PBKDF2",
        hash: "SHA512",
        length: 16,
        rounds: 4000 + Math.floor(Math.random() * 1000),
        salt: CryptoService.randomBytes(16),
        version: 1
    };
    return this.perform(password, data).then(function(mixed) {
        return {mixed: mixed, data: data};
    });
}

/**
 * Mix password
 * @param {string} password
 * @return {Promise[Buffer]}
 */
PasswordMixer.prototype.mix = function(password, data) {
    return this.perform(password, data).then(function(mixed) {
        return mixed;
    });
}

/**
 * Mix password and verify result
 * @param {string} password
 * @param {object} data
 * @return {Promise[object]}
 */
PasswordMixer.prototype.perform = function(password, data) {
    return Q().then(function() {
        if (data.algorithm == "PBKDF2") {
            if (data.hash != "SHA512") {
                throw new Error("Not supported hash algorithm '" + data.hash + "'");
            }
            if (data.version != 1) {
                throw new Error("Not supported version '" + data.version + "'");
            }
            if (data.salt.length != 16 || data.length != 16) {
                throw new Error("Invalid parameters");
            }
            return CryptoService.pbkdf2(new Buffer(password, "utf8"), data.salt, data.rounds, data.length, data.hash.toLowerCase());
        }
        throw new Error("Not supported algorithm '" + data.algorithm + "'");
    });
}

module.exports = new PasswordMixer();

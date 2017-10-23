var BrowserBuffer = require("../browserbuffer/BrowserBuffer");
var Q = require("q");
var Crypto = require("./Crypto");

function CryptoSubtle() {
}

/**
 * Is supported
 * @return {Promise[boolean]}
 */
CryptoSubtle.prototype.isSupported = function() {
    return Q().then(function() {
        var hasSupp = typeof(window) != "undefined" &&
            typeof(window.crypto) != "undefined" &&
            typeof(window.crypto.subtle) != "undefined" &&
            typeof(window.crypto.subtle.encrypt) != "undefined" &&
            typeof(window.crypto.subtle.decrypt) != "undefined" &&
            typeof(window.crypto.subtle.digest) != "undefined" &&
            typeof(window.crypto.subtle.importKey) != "undefined";
        if (hasSupp) {
            return this.sha256(new Buffer(10)).then(function() {
                return true;
            }).fail(function() {
                return false;
            });
        }
        return false;
    }.bind(this));
}

/**
 * SHA-1 (20 bytes long)
 * @param  {Buffer} data
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.sha1 = function(data) {
    return Q().then(function() {
        if (!BrowserBuffer.isBuffer(data)) {
            throw new Error("Invalid argument: data - expected Buffer");
        }
        return window.crypto.subtle.digest({name: "SHA-1"}, BrowserBuffer.bufferToArray(data, false)).then(BrowserBuffer.arrayToBuffer);
    });
}

CryptoSubtle.prototype.sha1_check = function() {
    return this.sha1(Buffer.from("abc")).then(() => true).catch(() => false);
}

/**
 * SHA-256 (32 bytes long)
 * @param  {Buffer} data
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.sha256 = function(data) {
    return Q().then(function() {
        if (!BrowserBuffer.isBuffer(data)) {
            throw new Error("Invalid argument: data - expected Buffer");
        }
        return window.crypto.subtle.digest({name: "SHA-256"}, BrowserBuffer.bufferToArray(data, false)).then(BrowserBuffer.arrayToBuffer);
    });
}

/**
 * SHA-384 (48 bytes long)
 * @param  {Buffer} data
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.sha384 = function(data) {
    return Q().then(function() {
        if (!BrowserBuffer.isBuffer(data)) {
            throw new Error("Invalid argument: data - expected Buffer");
        }
        return window.crypto.subtle.digest({name: "SHA-384"}, BrowserBuffer.bufferToArray(data, false)).then(BrowserBuffer.arrayToBuffer);
    });
}

/**
 * SHA-512 (64 bytes long)
 * @param  {Buffer} data
 * @return {Promise[Buffer]}
 */
CryptoSubtle.prototype.sha512 = function(data) {
    return Q().then(function() {
        if (!BrowserBuffer.isBuffer(data)) {
            throw new Error("Invalid argument: data - expected Buffer");
        }
        return window.crypto.subtle.digest({name: "SHA-512"}, BrowserBuffer.bufferToArray(data, false)).then(BrowserBuffer.arrayToBuffer);
    });
}

/**
 * AES-256-CBC with PKCS7 padding encryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.aes256CbcPkcs7Encrypt = function(data, key, iv) {
    return Q().then(function() {
        if (!BrowserBuffer.isBuffer(data) || data.length == 0) {
            throw new Error("Invalid argument: data - expected not empty Buffer");
        }
        if (!BrowserBuffer.isBuffer(key) || key.length != 32) {
            throw new Error("Invalid argument: key - expected Buffer 32 bytes long");
        }
        if (!BrowserBuffer.isBuffer(iv) || iv.length != 16) {
            throw new Error("Invalid argument: iv - expected Buffer 16 bytes long");
        }
        return window.crypto.subtle.importKey("raw", BrowserBuffer.bufferToArray(key, false), "AES-CBC", true, ["encrypt"]).then(function(key) {
            return window.crypto.subtle.encrypt({name: "AES-CBC", iv: BrowserBuffer.bufferToArray(iv, false)}, key, BrowserBuffer.bufferToArray(data, false));
        }).then(BrowserBuffer.arrayToBuffer);
    });
}

/**
 * AES-256-CBC with PKCS7 padding decryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.aes256CbcPkcs7Decrypt = function(data, key, iv) {
    return Q().then(function() {
        if (!BrowserBuffer.isBuffer(data) || data.length == 0) {
            throw new Error("Invalid argument: data - expected not empty Buffer");
        }
        if (!BrowserBuffer.isBuffer(key) || key.length != 32) {
            throw new Error("Invalid argument: key - expected Buffer 32 bytes long");
        }
        if (!BrowserBuffer.isBuffer(iv) || iv.length != 16) {
            throw new Error("Invalid argument: iv - expected Buffer 16 bytes long");
        }
        return window.crypto.subtle.importKey("raw", BrowserBuffer.bufferToArray(key, false), "AES-CBC", true, ["decrypt"]).then(function(key) {
            return window.crypto.subtle.decrypt({name: "AES-CBC", iv: BrowserBuffer.bufferToArray(iv, false)}, key, BrowserBuffer.bufferToArray(data, false));
        }).then(BrowserBuffer.arrayToBuffer);
    });
}

/**
 * @param {string} password
 * @param {Buffer} salt
 * @param {number} rounds
 * @param {number} length
 * @param {string} algorithm
 *
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.pbkdf2 = function(password, salt, rounds, length, algorithm = "sha1") {
    const shamap = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
    algorithm = shamap[algorithm] || algorithm;
    return Q().then(() => {
        return window.crypto.subtle.importKey("raw", Buffer.from(password), {name: "PBKDF2"}, false, ["deriveBits"]).then((key) => {
            return window.crypto.subtle.deriveBits({
                name: "PBKDF2",
                salt: salt,
                iterations: rounds,
                hash: {name: algorithm}
            }, key, length * 8).then(BrowserBuffer.arrayToBuffer);
        });
    });
};

CryptoSubtle.prototype.pbkdf2_vary = function(pass, salt, iters, keylen, digest = 'sha1') {
    return digest;
};

CryptoSubtle.prototype.pbkdf2_check = function(digest) {
    var deferred = Q.defer();
    this.pbkdf2("a", new Buffer(16), 1, 16, digest)
    .then(() => deferred.resolve(true))
    .catch(() => deferred.resolve(false));

    return deferred.promise;
};

// HMAC helper
function hmac(digest) {
    return function(key, data) {
        var algorithm = {
            name: "HMAC",
            hash: { name: digest }
        };
        return window.crypto.subtle.importKey(
            "raw",
            BrowserBuffer.bufferToArray(key, false),
            algorithm,
            false,
            ["sign"]
        ).then((symmetric) => {
            return window.crypto.subtle.sign(
                algorithm,
                symmetric,
                BrowserBuffer.bufferToArray(data, false)
            );
        }).then(BrowserBuffer.arrayToBuffer);
    };
};

/**
 * HMAC-SHA-1
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.hmacSha1   = hmac("SHA-1");

/**
 * HMAC-SHA-256
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.hmacSha256 = hmac("SHA-256");

/**
 * HMAC-SHA-512
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
CryptoSubtle.prototype.hmacSha512 = hmac("SHA-512");

/**
 * AES-256-CBC with PKCS7 padding and SHA-256 HMAC with NIST compatible KDF.
 * @param {Buffer}  data
 * @param {Buffer}  key32
 * @param {boolean} deterministic, default: false
 * @param {number}  taglen, default: 16
 * @return {Buffer}
 */
CryptoSubtle.prototype.aes256CbcHmac256Encrypt = function(data, key32, deterministic, taglen) {
    // TODO: use generic handlers before subtle, worker or crypto
    return Crypto.aes256CbcHmac256Encrypt.apply(Crypto, arguments);
};

/**
 * AES-256-CBC with PKCS7 padding and SHA-256 HMAC with NIST compatible KDF.
 * @param {Buffer} data
 * @param {Buffer} key32
 * @param {number} taglen, default: 16
 * @return {Buffer}
 */
CryptoSubtle.prototype.aes256CbcHmac256Decrypt = function(data, key, taglen) {
    return Crypto.aes256CbcHmac256Decrypt.apply(Crypto, arguments);
};

CryptoSubtle.prototype.hkdfSha256_check = function() {
    return Q()
        .then(() => this.hkdf("kdf key", "kdf salt", 16))
        .then((buf) => buf.toString('hex') == '3f0211629a98c93d5a65ec116693d235')
        .catch(() => false);
};

CryptoSubtle.prototype.hkdfSha256 = function(key, salt, info, len) {
    if (typeof info == "number" && !len) {
        len  = info;
        info = Buffer.alloc(0);
    }
    if (!Buffer.isBuffer(key))
        key = Buffer.from(key);
    if (!Buffer.isBuffer(salt))
        salt = Buffer.from(salt);
    if (!Buffer.isBuffer(info))
        info = Buffer.from(info);
    
    var algorithm = {
        name: "HKDF", 
        hash: { name: "SHA-256" }, 
        salt: salt.buffer,
        info: info.buffer
    };
    return window.crypto.subtle.importKey("raw", key.buffer, algorithm, false, ["deriveBits"])
        .then(key => window.crypto.subtle.deriveBits(algorithm, key, 8*len))
        .then(ab => Buffer.from(ab));
};

module.exports = new CryptoSubtle();
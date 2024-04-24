var Rng = require("./Rng");

module.exports = new Service();

var Requester = require("./webworker/Requester");
var Q = require("q");
var CryptoSubtle = require("./CryptoSubtle");
var Crypto = require("./Crypto");
var privmxHandler = require("./privmx-handler");

var isNode = typeof process !== 'undefined' && !!process.versions && !!process.versions.node;

function Service() {
    this.rng = new Rng();
    this.handlers = [];
    this.initialized = false;
    this.entropy = new Buffer(0);
    this.maxEntropy = 64 * 1024; // 64kb
    this.r = 0;
    this.timeEntropyEnabled = true;
}

/**
 * @param {Buffer} data
 */
Service.prototype.writeEntropy = function(data) {
    this.entropy = Buffer.concat([this.entropy, data]);
    if( this.entropy.length < this.maxEntropy )
        return;
    this.randomFeed(this.entropy);
    this.entropy = new Buffer(0);
};

Service.prototype.startEntropy = function() {
    var callback = (event) => {
        this.r++;
        var data = "";
        for(var key in event)
        {
            if( typeof(event[key]) === "function" )
                continue;
            try {
                data += key + event[key];
            } catch(e) {}
        }

        this.writeEntropy(Buffer.from(data));
    };

    if( typeof(document) !== "undefined" )
    {
        document.addEventListener("click", callback);
        document.addEventListener("dblclick", callback);
        document.addEventListener("mousemove", callback);
        document.addEventListener("keyup", callback);
        document.addEventListener("keydown", callback);
        document.addEventListener("keypress", callback);
        document.addEventListener("touchmove", callback);
        document.addEventListener("touchstart", callback);
        document.addEventListener("touchend", callback);
    }

    // Time Entropy
    var self = this;
    (function feeder() {
        var buffer = new Buffer(8);
        var date = new Date().getTime();

        buffer.writeInt32LE(self.r & 0xFFFFFFFF);
        buffer.writeInt32BE(date & 0xFFFFFFFF, 4);

        self.writeEntropy(buffer);
        
        if (self.timeEntropyEnabled) {
            setTimeout(feeder, self.randomBits(10).readUInt16BE(0));
        }
    })();
};

Service.prototype.feed = function(consumer) {
    this.r++;
    var data = new Buffer(256);
    // Generate random data
    if( typeof(window) !== "undefined" && window.crypto && window.crypto.getRandomValues )
        window.crypto.getRandomValues(data);
    else
        data = this.randomBytes(256);

    // Feed consumer
    if( typeof(consumer["randomFeed"]) === "function" )
        consumer.randomFeed(data);
    else if( typeof(consumer["execute"]) === "function" )
        consumer.execute("randomFeed", [data]);
    else
        return; // TODO: warn that consumer cannot be fed

    // Time [1000, 2000) ms
    var time = this.randomBits(10).readUInt16BE(0) + 1000;
    // Schedule next meal
    setTimeout(() => this.feed(consumer), time);
};

/**
 * @param string path - path to WebWorker script, optional
 */
Service.prototype.init = function(path) {
    if( this.initialized )
        return;

    this.startEntropy();
    this.handlers.push( require("../openssl/openssl-handler") );
    this.handlers.push(privmxHandler);
    this.handlers.push(CryptoSubtle);
    this.handlers.push( require("../rsa/rsa-subtle") );

    if( path )
    {
        var worker = new Requester(path);
        this.feed(worker);
        this.handlers.push(worker);
    }

    this.handlers.push({
        execute: (method, params) => {
            if( !Crypto[method] )
                return false;
            return Q().then(() => Crypto[method].apply(Crypto, params));
        }
    });

    this.handlers.push( require("../ecc/ecc-crypto") );
    if (isNode) {
        this.handlers.push( require("../rsa/rsa-crypto") );
    } else {
        this.handlers.push( require("../rsa/rsa-browser") );
    }
    
    // inject this service into handlers
    this.handlers.forEach(handler => {
        if (typeof handler["init"] == "function") 
            handler.init(this);
    });

    this.initialized = true;
};

Service.prototype.execute = function(method, params) {
    this.r++;
    this.init();
    // Conver arguments to array
    if( !Array.isArray(params) )
        params = Array.prototype.slice.call(params);

    for(var i = 0; i < this.handlers.length; ++i) {
        var handler = this.handlers[i];
        handler._state = handler._state || {};

        // check if handler is supported at all
        if ( handler["isSupported"]) {
            var state = handler._state["isSupported"];
            if (state === undefined) {
                // promise or bool
                state = handler["isSupported"].apply(handler);
                handler._state["isSupported"] = state;
            }
            if (state === false)
                continue;
            if (state !== true) {
                return state.then((result) => {
                    handler._state["isSupported"] = result;
                    return this.execute(method, params);
                });
            }
        }

        if ( ! handler[method] ) {
            // in case handler does not support method directly
            // also try more general "execute" method
            if ( ! handler["execute"] )
                // otherwise skip to the next handler
                continue;

            var result = handler.execute(method, params);
            if (result === false)
                // skip to the next handler
                continue;

            if ( ! Q.isPromiseAlike(result) ) {
                // TODO: it should return a promise !?!?!
                return Q.resolve(result);
            }

            return result;
        }

        if ( ! handler[method + "_check"] )
            return handler[method].apply(handler, params);

        // if mathod validates the same way as other method
        // field [method + "_check"] should be name of the other
        // method instead of validation function
        var checkMethod = handler[method + "_check"];
        if( typeof(checkMethod) !== "string" )
            checkMethod = method;

        var algo = checkMethod;
        var vary = "";
        if ( handler[checkMethod + "_vary"] ) {
            vary = handler[checkMethod + "_vary"].apply(handler, params);
            algo = algo + vary;
        }

        var state = handler._state[algo];
        if (state === false)
            continue;
        if (state === true) 
            return handler[method].apply(handler, params);
        if (state === undefined) {
            state = handler[checkMethod + "_check"].apply(handler, [vary]).then((result) => {
                handler._state[algo] = result;
            });
            handler._state[algo] = state;
        }
        return state.then(() => this.execute(method, params));
    }
    return Q.reject(new Error("unhandled method " + method));
};

//================================
//            RANDOM
//================================

Service.prototype.randomGenerator = function(seed) {
    return new Rng(seed);
}

/**
 * @param {Buffer} seed
 * @return {void}
 */
Service.prototype.randomFeed = function(seed) {
  this.rng.feed(seed);
}

/**
 * @return {number}
 */
Service.prototype.randomInt32 = function() {
  return this.rng.int32();
}

/**
 * @return {number}
 */
Service.prototype.randomDouble = function() {
  return this.rng.double();
}

/**
 * @param {number} count
 * @return {Buffer}
 */
Service.prototype.randomBytes = function(num) {
  return this.rng.bytes(num);
}

/**
 * @param {number} count
 * @return {Buffer}
 */
Service.prototype.randomBits = function(num) {
  return this.rng.bits(num);
}

/**
 * @param {BN} max
 * @return {BN}
 */
Service.prototype.randomBN = function(max) {
  return this.rng.bn(max);
}

//================================
//            CRYPTO
//================================

/**
 * HMAC-SHA-1
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.hmacSha1 = function(key, data) {
    return this.execute("hmacSha1", arguments);
}

/**
 * HMAC-SHA-256
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.hmacSha256 = function(key, data) {
    return this.execute("hmacSha256", arguments);
}

/**
 * HMAC-SHA-256 
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
 */
Service.prototype.hmacSha256Sync = function(key, data) {
    return Crypto.hmacSha256(key, data)
}

/**
 * HMAC-SHA-512
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.hmacSha512 = function(key, data) {
    return this.execute("hmacSha512", arguments);
}

/**
 * SHA-1 (20 bytes long)
 * @param  {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.sha1 = function(data) {
    return this.execute("sha1", arguments);
}

/**
 * SHA-256 (32 bytes long)
 * @param  {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.sha256 = function(data) {
    return this.execute("sha256", arguments);
}

/**
 * SHA-512 (64 bytes long)
 * @param  {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.sha512 = function(data) {
    return this.execute("sha512", arguments);
}

/**
 * AES-256-CBC with PKCS7 padding encryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Buffer}
 */
Service.prototype.aes256CbcPkcs7Encrypt = function(data, key, iv) {
    return this.execute("aes256CbcPkcs7Encrypt", arguments);
}

/**
 * AES-256-CBC with PKCS7 padding decryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Promise<Buffer>}
 */
Service.prototype.aes256CbcPkcs7Decrypt = function(data, key, iv) {
    return this.execute("aes256CbcPkcs7Decrypt", arguments);
}

/**
 * XTEA-ECB with PKCS7 padding encryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Promise<Buffer>}
 */
Service.prototype.xteaEcbPkcs7Encrypt = function(data, key) {
    return this.execute("xteaEcbPkcs7Encrypt", arguments);
}

/**
 * XTEA-ECB with PKCS7 padding decryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Promise<Buffer>}
 */
Service.prototype.xteaEcbPkcs7Decrypt = function(data, key) {
    return this.execute("xteaEcbPkcs7Decrypt", arguments);
}

/**
 * @param {Buffer} key
 * @param {Buffer} seed
 * @param {number} length
 * @return {Promise<Buffer>}
 */
Service.prototype.prf_tls12 = function(key, seed, length) {
    return this.execute("prf_tls12", arguments);
}

/**
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {number} length
 * @return {Promise<Buffer>}
 */
Service.prototype.hkdfSha256 = function(key, salt, length) {
    return this.execute("hkdfSha256", arguments);
}

/**
 * AES-256-CBC with PKCS7 padding and SHA-256 HMAC with NIST compatible KDF.
 * @param {Buffer}  data
 * @param {Buffer}  key32
 * @param {boolean} deterministic, default: false
 * @param {number}  taglen, default: 16
 * @return {Promise<Buffer>}
 */
Service.prototype.aes256CbcHmac256Encrypt = function(data, key, deterministic, taglen) {
    return this.execute("aes256CbcHmac256Encrypt", arguments);
}

/**
 * AES-256-CBC with PKCS7 padding and SHA-256 HMAC with NIST compatible KDF.
 * @param {Buffer} data
 * @param {Buffer} key32
 * @param {number} taglen, default: 16
 * @return {Promise<Buffer>}
 */
Service.prototype.aes256CbcHmac256Decrypt = function(data, key, taglen) {
    return this.execute("aes256CbcHmac256Decrypt", arguments);
}

/**
 * AES-256-ECB
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Promise<Buffer>}
 */
Service.prototype.aes256Ecb = function(data, key) {
    return this.execute("aes256Ecb", arguments);
}

/**
 * AES-256-ECB
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Service.prototype.aes256EcbSync = function(data, key) {
    return Crypto.aes256Ecb(data, key)
}

/**
 * AES-256-ECB
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Promise<Buffer>}
 */
Service.prototype.aes256EcbDecrypt = function(data, key) {
    return this.execute("aes256EcbDecrypt", arguments);
}

/**
 * AES-256-ECB
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Service.prototype.aes256EcbDecryptSync = function(data, key) {
    return Crypto.aes256EcbDecrypt(data, key)
}

//================================
//         CRYPTO PRIVFS
//================================

var funcs = [
    "privmxEncrypt",
    "privmxDecrypt",
    "privmxGetBlockSize",
    "privmxHasSignature",
    "privmxSetErrorOnMissingSignature",
    "privmxOptAesWithDettachedIv",
    "privmxOptAesWithAttachedIv",
    "privmxOptAesWithSignature",
    "privmxOptXtea",
    "privmxOptSignedCipher"
];
funcs.forEach(function(funcName) {
    Service.prototype[funcName] = function() {
        return this.execute(funcName, arguments);
    };
});

/**
 * Generate IV from index for AES (16 bytes long)
 * @param {Buffer} key
 * @param {number} idx Block index
 * @return {Promise<Buffer>}
 */
Service.prototype.generateIv = function(key, idx) {
    return this.execute("generateIv", arguments);
}

/**
 * Reduct 32-bytes long key to 16-bytes long by SHA-256 and take first 16 bytes
 * @param {Buffer} key
 * @return {Promise<Buffer>}
 */
Service.prototype.reductKey = function(key) {
    return this.execute("reductKey", arguments);
}

/**
 * AES-256-CBC with PKCS7 padding encryption without attached IV
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Promise<Buffer>}
 */
Service.prototype.aesEncryptWithDetachedIv = function(data, key, iv) {
    return this.execute("aesEncryptWithDetachedIv", arguments);
}

/**
 * AES-256-CBC with PKCS7 padding encryption with attached IV
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Promise<Buffer>}
 */
Service.prototype.aesEncryptWithAttachedIv = function(data, key, iv) {
    return this.execute("aesEncryptWithAttachedIv", arguments);
}

/**
 * AES-256-CBC with PKCS7 padding encryption with attached random IV
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Promise<Buffer>}
 */
Service.prototype.aesEncryptWithAttachedRandomIv = function(data, key) {
    return this.execute("aesEncryptWithAttachedIv", [data, key, this.randomBytes(16)]);
}

/**
 * XTEA-ECB with PKCS7 padding encryption
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Promise<Buffer>}
 */
Service.prototype.xteaEncrypt = function(data, key) {
    return this.execute("xteaEncrypt", arguments);
}

/**
 * XTEA-ECB with PKCS7 padding encryption (32-bytes long key is reducted to 16 bytes)
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Promise<Buffer>}
 */
Service.prototype.xteaEncrypt32 = function(data, key32) {
    return this.execute("xteaEncrypt32", arguments);
}

/**
 * @deprecated
 *
 * @param {Buffer} data
 * @param {Buffer} key32
 * @param {Buffer} iv16
 * @param {function} paramGetter
 * @return {Buffer}
 */
Service.prototype.decrypt = function(data, key32, iv16, paramGetter) {
    return this.execute("decrypt", arguments);
}

//================================
//            PBKDF2
//================================

/**
 * @param {string} password
 * @param {Buffer} salt
 * @param {number} rounds
 * @param {number} length
 * @param {string} algorithm
 *
 * @return {Promise<Buffer>}
 */
Service.prototype.pbkdf2 = function(password, salt, rounds, length, algorithm) {
    return this.execute("pbkdf2", arguments);
}

//================================
//             ECC
//================================

/**
 * @param {Ecc.PrivateKey} priv
 * @param {Buffer} hash
 * 
 * @return {Promise<Buffer>}
 */
Service.prototype.signToCompactSignature = function(priv, hash) {
    return this.execute("signToCompactSignature", arguments);
}

/**
 * @param {Ecc.PrivateKey} priv
 * @param {Buffer} message
 * 
 * @return {Promise<Buffer>}
 */
Service.prototype.signToCompactSignatureWithHash = function(priv, message) {
    return this.execute("signToCompactSignatureWithHash", arguments);
}

/**
 * @param {Ecc.PrivateKey} priv
 * @param {Ecc.PublicKey} pub
 * 
 * @return {Promise<Buffer>}
 */
Service.prototype.getSharedKey = function(priv, pub) {
    return this.execute("getSharedKey", arguments);
}

/**
 * @param {Ecc.PrivateKey} priv
 * @param {Ecc.PublicKey} pub
 * @param {Buffer} data
 * 
 * @return {Promise<Buffer>}
 */
Service.prototype.eciesEncrypt = function(priv, pub, data) {
    return this.execute("eciesEncrypt", arguments);
}

/**
 * @param {Ecc.PrivateKey} priv
 * @param {Ecc.PublicKey} pub
 * @param {Buffer} data
 * 
 * @return {Promise<Buffer>}
 */
Service.prototype.eciesDecrypt = function(priv, pub, data) {
    return this.execute("eciesDecrypt", arguments);
}

/**
 * @param {Ecc.PublicKey} pub
 * @param {Buffer} hash
 * @param {Buffer} signature
 * 
 * @return {Promise<Buffer>}
 */
Service.prototype.verifyCompactSignature = function(pub, hash, signature) {
    return this.execute("verifyCompactSignature", arguments);
}

/**
 * @param {Ecc.PublicKey} pub
 * @param {Buffer} message
 * @param {Buffer} signature
 * 
 * @return {Promise<Buffer>}
 */
Service.prototype.verifyCompactSignatureWithHash = function(pub, message, signature) {
    return this.execute("verifyCompactSignatureWithHash", arguments);
}

/**
 * @param {Ecc.ExtKey} ext
 * @param {number} idx
 * 
 * @return {Promise<Ecc.ExtKey>}
 */
Service.prototype.deriveHardened = function(ext, idx) {
    return this.execute("deriveHardened", arguments);
}

/**
 * Generates random Ecc PrivateKey in openssl format
 *
 * @return {Promise<string>} - PrivateKey in PEM format
 */
Service.prototype.eccGenerateKey = function() {
    return this.execute("eccGenerateKey", arguments);
};

/**
 * Generates ECDSA signature
 *
 * @param {string|Buffer|PrivateKey} priv - ecc private key
 * @param {Buffer} data - data to sign
 *
 * @param {Promise<Buffer>} - ecc signature in DER format
 */
Service.prototype.ecdsaSign = function(priv, data) {
    return this.execute("ecdsaSign", arguments);
};

/**
 * Verifies ECDSA signature
 *
 * @param {string|Buffer|PublicKey} pub - ecc public key
 * @param {Buffer} signature
 * @param {Buffer} data
 *
 * @return {Promise<boolean>}
 */
Service.prototype.ecdsaVerify = function(pub, signature, data) {
    return this.execute("ecdsaVerify", arguments);
};

//================================
//              BIP39
//================================

/**
 * @param {number} number
 * @param {string} password
 * 
 * @return {Promise<Bip39Result>}
 */
Service.prototype.bip39Generate = function(strength, password) {
    return this.execute("bip39FromEntropy", [this.randomBytes(strength / 8), password]);
}

/**
 * @param {Buffer} entropy
 * @param {string} password
 * 
 * @return {Promise<Bip39Result>}
 */
Service.prototype.bip39FromEntropy = function(entropy, password) {
    return this.execute("bip39FromEntropy", arguments);
}

/**
 * @param {Buffer} mnemonic
 * @param {string} password
 * 
 * @return {Promise<Bip39Result>}
 */
Service.prototype.bip39FromMnemonic = function(mnemonic, password) {
    return this.execute("bip39FromMnemonic", arguments);
}

/**
 * @param {Buffer} mnemonic
 * @param {string} password
 * 
 * @return {Promise<Ecc.ExtKey>}
 */
Service.prototype.bip39GetExtKey = function(mnemonic, password) {
    return this.execute("bip39GetExtKey", arguments);
}

//================================
//              SRP
//================================

/**
 * @param {Buffer} N
 * @param {Buffer} g
 * @param {string} I
 * @param {string} P
 * 
 * @return {Promise<RegisterResult>}
 */
Service.prototype.srpRegister = function(N, g, I, P) {
    return this.execute("srpRegister", [N, g, I, P, this.randomBytes(16)]);
}

/**
 * @param {Buffer} N
 * @param {Buffer} g
 * @param {Buffer} s
 * @param {Buffer} B
 * @param {Buffer} k
 * @param {string} I
 * @param {string} P
 * 
 * @return {Promise<LoginStep1Result>}
 */
Service.prototype.srpLoginStep1 = function(N, g, s, B, k, I, P) {
    return this.execute("srpLoginStep1", [N, g, s, B, k, I, P, this.randomBytes(64)]);
}

/**
 * @param {Buffer} clientM2
 * @param {Buffer} serverM2
 * 
 * @return {Promise<void>}
 */
Service.prototype.srpLoginStep2 = function(clientM2, serverM2) {
    return this.execute("srpLoginStep2", arguments);
}

//================================
//              RSA
//================================

/**
 * @param {nubmer} bits
 * @return {Promise<string>}
 */
Service.prototype.rsaGenerateKey = function(bits) {
    return this.execute("rsaGenerateKey", arguments);
};

/**
 * @param {nubmer} bits
 * @param {Buffer} seed
 * @return {Promise<string>}
 */
Service.prototype.rsaDeriveKey = function(bits, seed) {
    return this.execute("rsaDeriveKey", arguments);
};

/**
 * @param {string} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.rsaOaepEncrypt = function(key, data) {
    return this.execute("rsaOaepEncrypt", arguments);
};

/**
 * @param {string} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.rsaOaepDecrypt = function(key, data) {
    return this.execute("rsaOaepDecrypt", arguments);
};

/**
 * @param {string} key
 * @param {Buffer} data
 * @return {Promise<Buffer>}
 */
Service.prototype.rsaSign = function(key, data) {
    return this.execute("rsaSign", arguments);
};

/**
 * @param {string} key
 * @param {Buffer} signature
 * @param {Buffer} data
 * @return {Promise<boolean>}
 */
Service.prototype.rsaVerify = function(key, signature, data) {
    return this.execute("rsaVerify", arguments);
};

/**
 * @param {string} key
 * @param {string} passphrase
 * @return {Promise<string>}
 */
Service.prototype.encryptPrivateKey = function(key, passphrase) {
    return this.execute("encryptPrivateKey", arguments);
};

/**
 * @param {string} enckey
 * @param {string} passphrase
 * @return {Promise<string>}
 */
Service.prototype.decryptPrivateKey = function(enckey, passphrase) {
    return this.execute("decryptPrivateKey", arguments);
};

/**
 * Extract Public Key from Private Key
 *
 * @param {string|Buffer} priv - private key in DER or PEM format
 *
 * @return {Promise<string>}
 */
Service.prototype.extractPublicKey = function(priv) {
    return this.execute("extractPublicKey", arguments);
};

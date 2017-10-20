module.exports = new Crypto();

var CryptoService = require("./Service");
var _crypto = require("crypto");
var XTEA = require("xtea");
var BrowserBuffer = require("../browserbuffer/BrowserBuffer");
var IllegalArgumentException = require("privmx-exception").IllegalArgumentException;
var Ecc = require("../ecc");
var SrpLogic = require("../srp").SrpLogic;
var BN = require("bn.js");
var bip39 = require("bip39");
var LazyMap = require("../utils/LazyMap");
var Q = require("q");

function Crypto() {
}

/**
 * HMAC-SHA-1
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
 */
Crypto.prototype.hmacSha1 = function(key, data) {
    return _crypto.createHmac("sha1", key).update(data).digest();
}

/**
 * HMAC-SHA-256
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
 */
Crypto.prototype.hmacSha256 = function(key, data) {
    return _crypto.createHmac("sha256", key).update(data).digest();
}

/**
 * HMAC-SHA-512
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
 */
Crypto.prototype.hmacSha512 = function(key, data) {
    return _crypto.createHmac("sha512", key).update(data).digest();
}

/**
 * SHA-1 (20 bytes long)
 * @param  {Buffer} data
 * @return {Buffer}
 */
Crypto.prototype.sha1 = function(data) {
    return _crypto.createHash("sha1").update(data).digest();
}

/**
 * SHA-256 (32 bytes long)
 * @param  {Buffer} data
 * @return {Buffer}
 */
Crypto.prototype.sha256 = function(data) {
    return _crypto.createHash("sha256").update(data).digest();
}

/**
 * SHA-512 (64 bytes long)
 * @param  {Buffer} data
 * @return {Buffer}
 */
Crypto.prototype.sha512 = function(data) {
    return _crypto.createHash("sha512").update(data).digest();
}

/**
 * AES-256-CBC with PKCS7 padding encryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Buffer}
 */
Crypto.prototype.aes256CbcPkcs7Encrypt = function(data, key, iv) {
    if (!BrowserBuffer.isBuffer(data) || data.length == 0) {
        throw new IllegalArgumentException("data", data);
    }
    if (!BrowserBuffer.isBuffer(key) || key.length != 32) {
        throw new IllegalArgumentException("key", key);
    }
    if (!BrowserBuffer.isBuffer(iv) || iv.length != 16) {
        throw new IllegalArgumentException("iv", iv);
    }
    var cipher = _crypto.createCipheriv("aes-256-cbc", key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

/**
 * AES-256-CBC encryption without padding (data length must be multiple of 16)
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Buffer}
 */
Crypto.prototype.aes256CbcNoPadEncrypt = function(data, key, iv) {
    if (!BrowserBuffer.isBuffer(data) || data.length == 0 || data.length % 16 != 0) {
        throw new IllegalArgumentException("data", data);
    }
    if (!BrowserBuffer.isBuffer(key) || key.length != 32) {
        throw new IllegalArgumentException("key", key);
    }
    if (!BrowserBuffer.isBuffer(iv) || iv.length != 16) {
        throw new IllegalArgumentException("iv", iv);
    }
    var cipher = _crypto.createCipheriv("aes-256-cbc", key, iv);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

/**
 * AES-256-CBC with PKCS7 padding decryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Buffer}
 */
Crypto.prototype.aes256CbcPkcs7Decrypt = function(data, key, iv) {
    if (!BrowserBuffer.isBuffer(data) || data.length == 0) {
        throw new IllegalArgumentException("data", data);
    }
    if (!BrowserBuffer.isBuffer(key) || key.length != 32) {
        throw new IllegalArgumentException("key", key);
    }
    if (!BrowserBuffer.isBuffer(iv) || iv.length != 16) {
        throw new IllegalArgumentException("iv", iv);
    }
    var cipher = _crypto.createDecipheriv("aes-256-cbc", key, iv)
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

/**
 * AES-256-CBC decryption without padding (data length must be multiple of 16)
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Buffer}
 */
Crypto.prototype.aes256CbcNoPadDecrypt = function(data, key, iv) {
    if (!BrowserBuffer.isBuffer(data) || data.length == 0 || data.length % 16 != 0) {
        throw new IllegalArgumentException("data", data);
    }
    if (!BrowserBuffer.isBuffer(key) || key.length != 32) {
        throw new IllegalArgumentException("key", key);
    }
    if (!BrowserBuffer.isBuffer(iv) || iv.length != 16) {
        throw new IllegalArgumentException("iv", iv);
    }
    var cipher = _crypto.createDecipheriv("aes-256-cbc", key, iv)
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

/**
 * XTEA-ECB with PKCS7 padding encryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Crypto.prototype.xteaEcbPkcs7Encrypt = function(data, key) {
    if (!BrowserBuffer.isBuffer(data) || data.length == 0) {
        throw new IllegalArgumentException("data", data);
    }
    if (!BrowserBuffer.isBuffer(key) || key.length != 16) {
        throw new IllegalArgumentException("key", key);
    }
    return XTEA.encrypt(data, key, "ecb");
}

/**
 * XTEA-ECB with PKCS7 padding decryption
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Crypto.prototype.xteaEcbPkcs7Decrypt = function(data, key) {
    if (!BrowserBuffer.isBuffer(data) || data.length == 0) {
        throw new IllegalArgumentException("data", data);
    }
    if (!BrowserBuffer.isBuffer(key) || key.length != 16) {
        throw new IllegalArgumentException("key", key);
    }
    return XTEA.decrypt(data, key, "ecb");
}

/**
 * Key Derivation Function
 * See: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
 * @param {string} algo
 * @param {number} length
 * @param {Buffer} key
 * @param {Object | string} options or label, default: {}
 * @return {Buffer}
 */
Crypto.prototype.kdf = function(algo, length, key, options) {
    if( !options )
        options = {};

    if( typeof options === "string" )
    {
        options = {
            label: options
        };
    }

    var counters = options.counters === false ? false : true;
    var feedback = options.feedback === false ? false : true;

    var seed = new Buffer("");

    var opt2buffer = function(opt) {
        if( typeof opt === "string" )
            return new Buffer(opt);
        if( opt instanceof Buffer )
            return opt;
        return new Buffer("");
    };

    if( options.seed instanceof Buffer )
        seed = options.seed;
    else
    {

        var label = opt2buffer(options.label);
        var context = opt2buffer(options.context);
        seed = new Buffer( label.length + context.length + 5 );
        label.copy(seed);
        seed.writeUInt8(0, label.length);
        context.copy(seed, label.length + 1);
        seed.writeUInt32BE(length, label.length + context.length + 1);
    }

    var k = opt2buffer(options.iv);
    var result = new Buffer("");
    var i = 1;
    while(result.length < length)
    {
        var input = new Buffer("");
        if( feedback )
            input = k;

        if( counters )
        {
            var count = new Buffer(4);
            count.writeUInt32BE(i++);
            input = Buffer.concat([input, count]);
        }
        input = Buffer.concat([input, seed]);
        k = _crypto.createHmac(algo, key).update(input).digest();
        result = Buffer.concat([result, k]);
    }

    return result.slice(0, length);
}

/**
 * Derives encryption and authentication keys from a given secret key
 * @param {string} algo
 * @param {Buffer} key
 * @param {number} kelen, default: 32
 * @param {number} kmlen, default: 32
 * @return {Buffer[]}
 */
Crypto.prototype.getKEM = function(algo, key, kelen, kmlen) {
    if( !kelen && kelen !== 0  )
        kelen = 32;
    if( !kmlen && kmlen !== 0 )
        kmlen = 32;

    var kEM = this.kdf(algo, kelen + kmlen, key, "key expansion");
    var kE = kEM.slice(0, kelen);
    var kM = kEM.slice(kelen);

    return [kE, kM];
}

/**
 * AES-256-CBC with PKCS7 padding and SHA-256 HMAC with NIST compatible KDF.
 * @param {Buffer}  data
 * @param {Buffer}  key32
 * @param {boolean} deterministic, default: false
 * @param {number}  taglen, default: 16
 * @return {Buffer}
 */
Crypto.prototype.aes256CbcHmac256Encrypt = function(data, key32, deterministic, taglen)
{
    if( !taglen && taglen !== 0 )
        taglen = 16;

    var tmp = this.getKEM("sha256", key32);
    var kE = tmp[0], kM = tmp[1];

    var cipher = null;
    var tmp = null;
    if( deterministic )
        tmp = CryptoService.hmacSha256(key32, data);
    else
        tmp = CryptoService.randomBytes(16);

    return Q(tmp).then((iv) => {
        iv = iv.slice(0, 16);
        var prefix = new Buffer(16);
        prefix.fill(0);
        data = Buffer.concat([prefix, data]);
        return CryptoService.aes256CbcPkcs7Encrypt(data, kE, iv);
    }).then((c) => {
        cipher = c;
        return CryptoService.hmacSha256(kM, cipher);
    }).then((tag) => {
        tag = tag.slice(0, taglen);
        return Buffer.concat([cipher, tag]);
    }).then((value) => {
        return value;
    });
}

/**
 * AES-256-CBC with PKCS7 padding and SHA-256 HMAC with NIST compatible KDF.
 * @param {Buffer} data
 * @param {Buffer} key32
 * @param {number} taglen, default: 16
 * @return {Buffer}
 */
Crypto.prototype.aes256CbcHmac256Decrypt = function(data, key32, taglen)
{
    if( !taglen && taglen !== 0 )
        taglen = 16;

    var tmp = this.getKEM("sha256", key32);
    var kE = tmp[0], kM = tmp[1];

    var tag = data.slice(data.length - taglen);
    data = data.slice(0, data.length - taglen);

    return CryptoService.hmacSha256(kM, data).then((rtag) => {
        rtag = rtag.slice(0, taglen);
        if( !tag.equals(rtag) )
            throw new Error("Wrong message security tag");

        var iv = data.slice(0, 16);
        data = data.slice(16);

        return CryptoService.aes256CbcPkcs7Decrypt(data, kE, iv);
    });
}

/**
 * @param {Buffer} key
 * @param {Buffer} seed
 * @param {number} length
 * @return {Buffer}
 */
Crypto.prototype.prf_tls12 = function (key, seed, length) {
    var a = seed;
    var result = Buffer.alloc(0);
    while (result.length < length) {
        a = this.hmacSha256(key, a);
        result = Buffer.concat([result, this.hmacSha256(key, Buffer.concat([a, seed]))]);
    }
    return result.slice(0, length);
};

Crypto.prototype.hkdfSha256 = function(key, salt, info, len) {
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

    var output = Buffer.alloc(len);
    
    var prk = this.hmacSha256(salt, key);
    var offset = 0;
    var t = Buffer.alloc(0);
    var i = 1;
    while(offset < len) {
        t = this.hmacSha256(prk, Buffer.concat([t, info, Buffer.from([i++])]));
        offset += t.copy(output, offset, 0, Math.min(t.length, len - offset));
    }
    return output;
};    

/**
 * AES-256-ECB
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Crypto.prototype.aes256Ecb = function (data, key) {
    if (!BrowserBuffer.isBuffer(data) || data.length == 0 || data.length % 16 != 0) {
        throw new IllegalArgumentException("data", data);
    }
    if (!BrowserBuffer.isBuffer(key) || (key.length != 32 && key.length != 16)) {
        throw new IllegalArgumentException("key", key);
    }
    var cipher = _crypto.createCipheriv("aes-256-ecb", key, '');
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
};

/**
 * AES-256-ECB
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Crypto.prototype.aes256EcbDecrypt = function (data, key) {
    if (!BrowserBuffer.isBuffer(data) || data.length == 0 || data.length % 16 != 0) {
        throw new IllegalArgumentException("data", data);
    }
    if (!BrowserBuffer.isBuffer(key) || key.length != 32) {
        throw new IllegalArgumentException("key", key);
    }
    var cipher = _crypto.createDecipheriv("aes-256-ecb", key, '');
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
};

//================================
//       CRYPTO PRIVFS
//================================

/**
 * Constants
 */
Crypto.prototype.TYPES = {
    AES_256_CBC_PKC7_NO_IV: 1,
    AES_256_CBC_PKC7_WITH_IV: 2,
    XTEA_ECB: 3,
    AES_256_CBC_PKC7_WITH_IV_AND_HMAC_SHA256: 4
};

/**
 * Create 1-byte long buffer
 * @param {int} int
 * @return {Buffer}
 */
Crypto.prototype.bufferFromInt = function(int) {
    var typeBuf = new Buffer(1);
    typeBuf.writeUInt8(int, 0);
    return typeBuf;
};

/**
 * Generate IV from index for AES (16 bytes long)
 * @param {Buffer} key
 * @param {number} idx Block index
 * @return {Buffer}
 */
Crypto.prototype.generateIv = function(key, idx) {
    return this.hmacSha256(key, new Buffer("iv" + idx, "utf8")).slice(0, 16);
};

/**
 * Reduct 32-bytes long key to 16-bytes long by SHA-256 and take first 16 bytes
 * @param {Buffer} key
 * @return {Buffer}
 */
Crypto.prototype.reductKey = function(key) {
    return this.sha256(key).slice(0, 16);
};

/**
 * AES-256-CBC with PKCS7 padding encryption without attached IV
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Buffer}
 */
Crypto.prototype.aesEncryptWithDetachedIv = function(data, key, iv) {
    return Buffer.concat([this.bufferFromInt(this.TYPES.AES_256_CBC_PKC7_NO_IV), this.aes256CbcPkcs7Encrypt(data, key, iv)]);
};

/**
 * AES-256-CBC with PKCS7 padding encryption with attached IV
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @return {Buffer}
 */
Crypto.prototype.aesEncryptWithAttachedIv = function(data, key, iv) {
    return Buffer.concat([this.bufferFromInt(this.TYPES.AES_256_CBC_PKC7_WITH_IV), iv, this.aes256CbcPkcs7Encrypt(data, key, iv)]);
};

/**
 * AES-256-CBC with PKCS7 padding encryption with attached random IV
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Crypto.prototype.aesEncryptWithAttachedRandomIv = function(data, key) {
    return this.aesEncryptWithAttachedIv(data, key, CryptoService.randomBytes(16));
};

/**
 * XTEA-ECB with PKCS7 padding encryption
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Crypto.prototype.xteaEncrypt = function(data, key) {
    return Buffer.concat([this.bufferFromInt(this.TYPES.XTEA_ECB), this.xteaEcbPkcs7Encrypt(data, key)]);
};

/**
 * XTEA-ECB with PKCS7 padding encryption (32-bytes long key is reducted to 16 bytes)
 * @deprecated
 * 
 * @param {Buffer} data
 * @param {Buffer} key
 * @return {Buffer}
 */
Crypto.prototype.xteaEncrypt32 = function(data, key32) {
    return this.xteaEncrypt(data, this.reductKey(key32));
};

Crypto.prototype.defaultParamGetter = function(map, name) {
    if (name == "key16") {
        return this.reductKey(map.get("key32"));
    }
};

Crypto.prototype.createParamsLazyMap = function(key32, iv16, paramGetter) {
    var map = new LazyMap(paramGetter || this.defaultParamGetter.bind(this));
    if (key32 != null) {
        map.key32 = key32;
    }
    if (iv16 != null) {
        map.iv16 = iv16;
    }
    return map;
};

/**
 * @deprecated
 *
 * @param {Buffer} data
 * @param {Buffer} key32
 * @param {Buffer} iv16
 * @param {function} paramGetter
 * @return {Buffer}
 */
Crypto.prototype.decrypt = function(data, key32, iv16, paramGetter) {
    var params = this.createParamsLazyMap(key32, iv16, paramGetter);
    var type = data.readUInt8(0);
    if (type == this.TYPES.AES_256_CBC_PKC7_NO_IV) {
        return this.aes256CbcPkcs7Decrypt(data.slice(1), params.get("key32"), params.get("iv16"));
    }
    if (type == this.TYPES.AES_256_CBC_PKC7_WITH_IV) {
        return this.aes256CbcPkcs7Decrypt(data.slice(17), params.get("key32"), data.slice(1, 17));
    }
    if (type == this.TYPES.XTEA_ECB) {
        return this.xteaEcbPkcs7Decrypt(data.slice(1), params.get("key16"));
    }
    if (type == this.TYPES.AES_256_CBC_PKC7_WITH_IV_AND_HMAC_SHA256) {
        return this.aes256CbcHmac256Decrypt(data.slice(1), params.get("key32"));
    }
    throw new Error("Unknown decryption type " + type);
};

// XXX: Moved from CryptoPrivFs, this wasn't used anywere and in Crypto already exist this method
/**
 * AES-256-CBC with PKCS7 padding encryption with attached random IV and HMAC SHA256
 * @param {Buffer}  data
 * @param {Buffer}  key32
 * @param {boolean} deterministic, default: false
 * @param {number}  taglen, default: 16
 * @return {Buffer}
 */
/*
CryptoPrivFs.prototype.aes256CbcHmac256Encrypt = function(data, key32, deterministic, taglen) {
    return Buffer.concat([
        this.bufferFromInt(this.TYPES.AES_256_CBC_PKC7_WITH_IV_AND_HMAC_SHA256),
        Crypto.aes256CbcHmac256Encrypt(data, key32, deterministic, taglen)
    ]);
};
*/

//================================
//          PBKDF2
//================================

/**
 * @param {string} password
 * @param {Buffer} salt
 * @param {number} rounds
 * @param {number} length
 * @param {string} algorithm
 *
 * @return {Buffer}
 */
Crypto.prototype.pbkdf2 = function(password, salt, rounds, length, algorithm) {
    return _crypto.pbkdf2Sync(password, salt, rounds, length, algorithm);
};

//================================
//           ECC
//================================

/**
 * @param {Ecc.PrivateKey} priv
 * @param {Buffer} hash
 * 
 * @return {Buffer}
 */
Crypto.prototype.signToCompactSignature = function(priv, hash) {
    return priv.signToCompactSignature(hash);
};

/**
 * @param {Ecc.PrivateKey} priv
 * @param {Buffer} message
 * 
 * @return {Buffer}
 */
Crypto.prototype.signToCompactSignatureWithHash = function(priv, message) {
    return priv.signToCompactSignature(this.sha256(message));
};

/**
 * @param {Ecc.PrivateKey} priv
 * @param {Ecc.PublicKey} pub
 * 
 * @return {Buffer}
 */
Crypto.prototype.getSharedKey = function(priv, pub) {
    return priv.getSharedKey(pub);
};

/**
 * @param {Ecc.PublicKey} pub
 * @param {Buffer} hash
 * @param {Buffer} signature
 * 
 * @return {Buffer}
 */
Crypto.prototype.verifyCompactSignature = function(pub, hash, signature) {
    return pub.verifyCompactSignature(hash, signature);
};

/**
 * @param {Ecc.PublicKey} pub
 * @param {Buffer} message
 * @param {Buffer} signature
 * 
 * @return {Buffer}
 */
Crypto.prototype.verifyCompactSignatureWithHash = function(pub, message, signature) {
    return pub.verifyCompactSignature(this.sha256(message), signature);
};

/**
 * @param {Ecc.ExtKey} ext
 * @param {number} idx
 * 
 * @return {Ecc.ExtKey}
 */
Crypto.prototype.deriveHardened = function(ext, idx) {
    return ext.deriveHardened(idx);
};

//================================
//              BIP39
//================================

/**
 * @param {number} number
 * @param {string} password
 * 
 * @return {Bip39Result}
 */
Crypto.prototype.bip39FromEntropy = function(entropy, password) {
    var mnemonic = bip39.entropyToMnemonic(entropy);
    var extKey = this.bip39GetExtKey(mnemonic, password);
    return {entropy: entropy, mnemonic: mnemonic, extKey: extKey};
};

/**
 * @param {Buffer} entropy
 * @param {string} password
 * 
 * @return {Bip39Result}
 */
Crypto.prototype.bip39FromMnemonic = function(mnemonic, password) {
    var entropy = bip39.mnemonicToEntropy(mnemonic);
    var extKey = this.bip39GetExtKey(mnemonic, password);
    return {entropy: entropy, mnemonic: mnemonic, extKey: extKey};
};

/**
 * @param {Buffer} mnemonic
 * @param {string} password
 * 
 * @return {Ecc.ExtKey}
 */
Crypto.prototype.bip39GetExtKey = function(mnemonic, password) {
    var seed = bip39.mnemonicToSeed(mnemonic, password);
    return Ecc.ExtKey.fromSeed(seed);
};

//================================
//            SRP
//================================

/**
 * @param {Buffer} N
 * @param {Buffer} g
 * @param {string} I
 * @param {string} P
 * @param {Buffor} s
 * 
 * @return {RegisterResult}
 */
Crypto.prototype.srpRegister = function(N, g, I, P, s) {
    var srp = new SrpLogic("sha256");
    var result = srp.register(new BN(N), new BN(g), I, P, s);
    return {
        s: result.s,
        v: result.v.toArrayLike(Buffer)
    };
};

/**
 * @param {Buffer} N
 * @param {Buffer} g
 * @param {Buffer} s
 * @param {Buffer} B
 * @param {Buffer} k
 * @param {string} I
 * @param {string} P
 * @param {Buffer} a
 * 
 * @return {LoginStep1Result}
 */
Crypto.prototype.srpLoginStep1 = function(N, g, s, B, k, I, P, a) {
    var srp = new SrpLogic("sha256");
    var result = srp.login_step1(new BN(N), new BN(g), s, new BN(B), I, P, new BN(a));
    return {
        A: result.A.toArrayLike(Buffer),
        K: result.K.toArrayLike(Buffer, "be", 32), // be - big-endian
        M1: result.M1.toArrayLike(Buffer),
        M2: result.M2.toArrayLike(Buffer)
    };
};

/**
 * @param {Buffer} clientM2
 * @param {Buffer} serverM2
 * 
 * @return {void}
 */
Crypto.prototype.srpLoginStep2 = function(clientM2, serverM2) {
    var srp = new SrpLogic("sha256");
    return srp.login_step2(new BN(clientM2), new BN(serverM2));
};

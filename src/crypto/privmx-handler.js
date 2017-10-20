var errorOnMissingSignature = true;

module.exports = {
    privmxEncrypt: encrypt,
    privmxDecrypt: decrypt,
    privmxGetBlockSize: getBlockSize,
    privmxHasSignature: hasSignature,
    
    privmxSetErrorOnMissingSignature: function(value) {
        errorOnMissingSignature = !!value;
    },
    privmxOptAesWithDettachedIv: function() {
        return {algorithm: "AES-256-CBC"};
    },
    privmxOptAesWithAttachedIv: function() {
        return {algorithm: "AES-256-CBC", attachIv: true};
    },
    privmxOptAesWithSignature: function() {
        return {algorithm: "AES-256-CBC", attachIv: true, hmac: "SHA-256"};
    },
    privmxOptXtea: function() {
        return {algorithm: "XTEA-ECB"};
    },
    privmxOptSignedCipher: function() {
        return {signed: true};
    }
};

var CryptoService = require("./Service");
var BrowserBuffer = require("../browserbuffer/BrowserBuffer");
var Q = require("q");

// Predefined types
const AES_256_CBC_PKCS7_NO_IV = 1
const AES_256_CBC_PKCS7_WITH_IV = 2;
const XTEA_ECB = 3;
const AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256 = 4;

// TODO: typings.ts
/*
interface EncryptOptions {
    algorithm: "AES-256-CBC" | "XTEA-ECB";
    attachIv?: boolean; // default false
    hmac?: "SHA-1" | "SHA-256" | "SHA-512"; // default none
    // aes256 with hmac options
    deterministic?: boolean; // default false
    taglen?: number; // default 16
};

interface DecryptOptions {
    // aes256 with hmac option
    taglen?: number; // default 16
    signed?: boolean // default false
}
*/

/**
 * Get source data size when a given blockSize is max size of cipher
 * @param {EncryptOptions} options
 * @param {number} blockSize
 * @return {number}
 */
function getBlockSize(options, blockSize) {
    var size = blockSize - 1;
    if (options.attachIv) {
        size -= 16;
    }
    if (options.hmac) {
        size -= typeof(options.taglen) == "undefined" ? 16 : options.taglen;
    }
    return size - (size % 16) - 1;
}

/**
 * Check if cipher has signature
 * @param {Buffer|number} data
 * @return {boolean}
 */
function hasSignature(data) {
    var nr = BrowserBuffer.isBuffer(data) ? data.readUInt8(0) : data;
    return nr == AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256;
}

/**
 * Privmx specific encryption
 * 
 * @param {EncryptOptions} options
 * @param {Buffer} data
 * @param {Buffer} key - 32 bytes
 * @param {Buffer} iv - 16 bytes (optional)
 * 
 * @return {Q.Promise<Buffer>}
 */
function encrypt(options, data, key, iv) {
    return Q().then(() => {
        if( key.length !== 32 )
            throw new Error("Encrypt invalid key length, required: 32, have: " + key.length + " " + key.toString("hex"));

        var hmac = options.hmac || false;
        var withIV = options.attachIv === true;

        switch(options.algorithm)
        {
            case "AES-256-CBC":
                if( hmac )
                {
                    if( hmac !== "SHA-256" || !withIV )
                        throw new Error("Only hmac SHA-256 with iv is supported for AES-256-CBC");
                    if( iv )
                        throw new Error("Cannot give IV to AES-256-CBC hmac SHA-256");

                    return CryptoService.aes256CbcHmac256Encrypt(data, key, options.deterministic, options.taglen).then((cipher) => {
                        return Buffer.concat([
                            new Buffer([AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256]), cipher
                        ]);
                    });
                }

                iv = iv || CryptoService.randomBytes(16);
                return CryptoService.aes256CbcPkcs7Encrypt(data, key, iv).then((cipher) => {
                    var buffers = [];
                    if( withIV )
                    {
                        buffers.push(new Buffer([AES_256_CBC_PKCS7_WITH_IV]));
                        buffers.push(iv);
                    }
                    else
                        buffers.push(new Buffer([AES_256_CBC_PKCS7_NO_IV]));
                    buffers.push(cipher);
                    return Buffer.concat(buffers);
                });

            case "XTEA-ECB":
                if( hmac || iv || withIV )
                    throw new Error("XTEA-ECB encryption doesn't support hmac and iv");

                return CryptoService.reductKey(key).then((reduced) => {
                    return CryptoService.xteaEcbPkcs7Encrypt(data, key).then((cipher) => {
                        return Buffer.concat([new Buffer([XTEA_ECB]), cipher]);
                    });
                });

            default:
                throw new Error("Unsupported encryption algorithm " + options.algorithm);
        }
    });
};

/**
 * Privmx specific decryption
 * 
 * @param {DecryptOptions} options - optional
 * @param {Buffer} data
 * @param {Buffer} key - 32 bytes
 * @param {Buffer} iv - 16 bytes (optional)
 * 
 * @return {Q.Promise<Buffer>}
 */
function decrypt(options, data, key, iv) {
    // if options not used
    if (BrowserBuffer.isBuffer(options))
    {
        iv = key;
        key = data;
        data = options;
        options = {};
    }

    return Q().then(() => {
        if( key.length !== 32 )
            throw new Error("Decrypt invalid key length, required: 32, have: " + key.length + " " + key.toString("hex"));
        if (options.signed && !hasSignature(data) && errorOnMissingSignature) {
            throw new Error("Missing required signature");
        }

        var type = data.readUInt8(0);
        switch(type)
        {
            case AES_256_CBC_PKCS7_NO_IV:
                if( !iv )
                    throw new Error("Missing IV");
                return CryptoService.aes256CbcPkcs7Decrypt(data.slice(1), key, iv);
            case AES_256_CBC_PKCS7_WITH_IV:
                return CryptoService.aes256CbcPkcs7Decrypt(data.slice(17), key, data.slice(1, 17));
            case XTEA_ECB:
                return CryptoService.reductKey(key).then((reduced) => {
                    return CryptoService.xteaEcbPkcs7Decrypt(data.slice(1), reduced);
                });
            case AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256:
                return CryptoService.aes256CbcHmac256Decrypt(data.slice(1), key, options.taglen);
            default:
                throw new Error("Unsupported type " + type);
        }
    });
};

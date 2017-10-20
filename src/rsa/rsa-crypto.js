module.exports = {
  init:              init,
  rsaGenerateKey:    rsaGenerateKey,
  rsaDeriveKey:      rsaDeriveKey,
  rsaOaepEncrypt:    rsaOaepEncrypt,
  rsaOaepDecrypt:    rsaOaepDecrypt,
  rsaSign:           rsaSign,
  rsaVerify:         rsaVerify
}

// will be injected
var service;
function init(_service) {
    service = _service;
}

const utils  = require("../openssl/openssl-utils");
const genrsa = require("./genrsa");
var crypto   = require("crypto");
var Q        = require("q");

const RSA_PKCS1_OAEP_PADDING = 4;

/**
 * @param {number} bits
 * @returns {Q.Promise<string>} generated PEM encoded private key
 */
function rsaGenerateKey(bits, seed) {
  return genrsa.generateKey(bits, service.randomGenerator(seed));
}

/**
 * @param {number} bits
 * @param {Buffer} seed
 * @returns {Q.Promise<string>} generated PEM encoded private key
 */
function rsaDeriveKey(bits, seed) {
  return genrsa.generateKey(bits, service.randomGenerator(seed));
}

// Uses SHA1 for OAEP padding and mgf1

/**
 * @param {string|Buffer} key PEM encoded public key; if private key is provided the public key is derived from it
 * @param {Buffer} data data to be encrypted (the length of the data has to be at least 40 bytes shorter than public key modulus length)
 * @returns {Q.Promise<Buffer>} encrypted data
 */
function rsaOaepEncrypt(key, data) {
  return Q().then(() => {
    if (!Buffer.isBuffer(data))
      data = Buffer.from(data);
    return crypto.publicEncrypt({key: key, padding: RSA_PKCS1_OAEP_PADDING}, data);
  });
}

/**
 * @param {string|Buffer} key PEM encoded private key
 * @param {Buffer} data data to be decrypted
 * @returns {Q.Promise<Buffer>} decrypted data
 */
function rsaOaepDecrypt(key, data) {
  return Q().then(() => {
    if (!Buffer.isBuffer(data))
      data = Buffer.from(data);
    return crypto.privateDecrypt({key: key, padding: RSA_PKCS1_OAEP_PADDING}, data);
  });
}

// Uses RSASSA-PCKS1-v1_5 with SHA-256

/**
 * @param {string|Buffer} key PEM encoded private key
 * @param {Buffer} data data to be signed
 * @returns {Q.Promise<Buffer>} binary signature of the data
 */
function rsaSign(key, data) {
  var rsa = utils.parsePem(key);
  if (!rsa || rsa.name != "PRIVATE KEY")
    return Q.reject(new Error("Invalid 'key' argument"));
  return Q().then(() => {
    var sign = crypto.createSign('RSA-SHA256');
    sign.write(data);
    return sign.sign(key);
  });
}

/**
 * @param {string|Buffer} key PEM encoded public key; if private key is provided the public key is derived from it
 * @param {Buffer} signature binary signature
 * @param {Buffer} data data to be verified
 * @returns {Q.Promise<boolean>} result of the verification
 */
function rsaVerify(key, signature, data) {
  var rsa = utils.parsePem(key);
  if (rsa && rsa.name == "PRIVATE KEY") {
    return service.extractPublicKey(key).then(pub => {
      return rsaVerify(pub, signature, data);
    });
  }
  if (!rsa || rsa.name != "PUBLIC KEY") 
    return Q.reject(new Error("Invalid 'key' argument"));
  return Q().then(() => {
    var verify = crypto.createVerify('RSA-SHA256');
    verify.write(data);
    return verify.verify(key, signature);
  });
}

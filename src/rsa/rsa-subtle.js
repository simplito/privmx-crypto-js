module.exports = {
  init:           init,
  isSupported:    isSupported,
  rsaGenerateKey: rsaGenerateKey,
  rsaOaepEncrypt: rsaOaepEncrypt,
  rsaOaepDecrypt: rsaOaepDecrypt,
  rsaSign:        rsaSign,
  rsaVerify:      rsaVerify
}

const utils = require("../openssl/openssl-utils");
var Q       = require("q");

// will be injected
var service;
function init(_service) {
    service = _service;
}

var crypto = (typeof(window) === "object") && window.crypto;

function isSupported() {
  if (!crypto || !crypto.subtle || !crypto.subtle.generateKey)
    return false;

  var key = 
    "-----BEGIN PRIVATE KEY-----\n" +
    "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA0CGzPfzAL1Q+FnDZ\n" +
    "KfsHb+T81YK6oN4LPLTFelcPQFmWvzteezi8xulmN9mQ+D6MztuPZr0kUyU+5ce6\n" +
    "AdQJkQIDAQABAkBIovpDL+qCmgvxGQExPYKi8m+qtC0d52BUl2I0CB4yfnBjuljI\n" +
    "npuPBRqGDubD1M/8VGnbMxASTBOjCvg7LEhhAiEA8rbgA+tWaEEoLJP/UJ8EnImy\n" +
    "5Jw8ABb++avKYQl9yo8CIQDbhjjUZS3yO218fgzJ2qnpoZs2H1XERpRXJQ1trM15\n" +
    "3wIgDE9yNUCudUM4wmoPPQuTtEzXofi6olaIQCmSbjGJC8kCIQCDiHTcrpNNJNaB\n" +
    "VXWMLPzKBA7f6v6U0EVpwcW+BWBIuQIhANGvd79Hg0cK79nGBYLc+byidnaX1Pb6\n" +
    "EwYWFXU/a9Yt\n" +
    "-----END PRIVATE KEY-----";

  var cipher = Buffer.from(
    "Xp5uW0NY8bvNJRXS0KSVXXZzMpqdwrWmQrx3f9SArsdBKcGguI030dB8FcIZD6OuGinfRKFDX5NsudI/wHb7xA==",
    "base64");

  return rsaOaepDecrypt(key, cipher).timeout(100).then(x => x.toString() == "abcd").catch(() => false);
}

function rsaGenerateKey(bits) {
  var defer = Q.defer();
  var algorithm = {
    name: 'RSA-OAEP',
    modulusLength: bits,
    publicExponent: new Uint8Array([1,0,1]),
    hash: { name: 'SHA-256' }
  };
  crypto.subtle.generateKey(algorithm, true, ['encrypt', 'decrypt'])
  .then((keys) => {
    crypto.subtle.exportKey('pkcs8', keys.privateKey)
    .then((ab) => {
      var result =  "-----BEGIN PRIVATE KEY-----\n" + 
                    utils.chunk(Buffer.from(ab).toString("base64"), 64) +
                    "-----END PRIVATE KEY-----";
      defer.resolve(result);
    });
  }, (reason) => { defer.reject(reason); });
  return defer.promise;
}

function rsaOaepEncrypt(key, data) {
  var defer = Q.defer();
  var algorithm = {
    name: 'RSA-OAEP',
    hash: { name: 'SHA-1' }
  };
  var rsa = utils.parsePem(key);
  if (rsa && rsa.name == "PRIVATE KEY") {
    return service.extractPublicKey(key).then(pub => {
      return rsaOaepEncrypt(pub, data);
    });
  }
  if (!rsa || rsa.name != "PUBLIC KEY") 
    return Q.reject(new Error("Invalid 'key' argument"));
  crypto.subtle.importKey('spki', rsa.data.buffer, algorithm, false, ['encrypt'])
  .then(key => crypto.subtle.encrypt(algorithm, key, data.buffer))
  .then(ab => defer.resolve(Buffer.from(ab)), 
        reason => defer.reject(reason));
  
  return defer.promise;
}

function rsaOaepDecrypt(key, data) {
  var defer = Q.defer();
  var algorithm = {
    name: 'RSA-OAEP',
    hash: { name: 'SHA-1' }
  };
  var rsa = utils.parsePem(key);
  if (!rsa || rsa.name != "PRIVATE KEY")
    return Q.reject(new Error("Invalid 'key' argument"));
  crypto.subtle.importKey('pkcs8', rsa.data.buffer, algorithm, false, ['decrypt'])
  .then(key => crypto.subtle.decrypt(algorithm, key, data.buffer))
  .then(ab => defer.resolve(Buffer.from(ab)), 
        reason => defer.reject(reason));
  
  return defer.promise;
}

function rsaSign(key, data) {
  var defer = Q.defer();
  var algorithm = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: 'SHA-256' }
  };
  var rsa = utils.parsePem(key);
  if (!rsa || rsa.name != "PRIVATE KEY")
    return Q.reject(new Error("Invalid 'key' argument"));
  crypto.subtle.importKey('pkcs8', rsa.data.buffer, algorithm, false, ['sign'])
  .then(key => crypto.subtle.sign(algorithm, key, data.buffer))
  .then(ab => defer.resolve(Buffer.from(ab)), 
        reason => defer.reject(reason));
  
  return defer.promise;
}

function rsaVerify(key, signature, data) {
  var defer = Q.defer();
  var algorithm = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: 'SHA-256' }
  };
  var rsa = utils.parsePem(key);
  if (rsa && rsa.name == "PRIVATE KEY") {
    return service.extractPublicKey(key).then(pub => {
      return rsaVerify(pub, signature, data);
    });
  }
  if (!rsa || rsa.name != "PUBLIC KEY") 
    return Q.reject(new Error("Invalid 'key' argument"));
  crypto.subtle.importKey('spki', rsa.data.buffer, algorithm, false, ['verify'])
  .then(key => crypto.subtle.verify(algorithm, key, signature.buffer, data.buffer))
  .then(ab => defer.resolve(ab), 
        reason => defer.reject(reason));
  return defer.promise;
}

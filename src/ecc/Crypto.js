var createHash = require('create-hash');
var createHmac = require("create-hmac");
var AES        = require("browserify-aes");

function sha256(buf) {
  return createHash("sha256").update(buf).digest();
}

function hash160(buffer) {
  return ripemd160(sha256(buffer))
}

function ripemd160(buffer) {
  return createHash('rmd160').update(buffer).digest()
}

function sha512(buf) {
  return createHash("sha512").update(buf).digest();
}

function sha256hmac(data, key) {
  return createHmac("sha256", key).update(data).digest();
}

function aesCbcEncode(msg, key, iv) {
  var cipher = AES.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([cipher.update(msg), cipher.final()]);
}

function aesCbcDecode( msg, key, iv ) {
  var cipher = AES.createDecipheriv("aes-256-cbc", key, iv)
  return Buffer.concat([cipher.update(msg), cipher.final()]);
}

module.exports = {
  ripemd160: ripemd160,
  hash160: hash160,
  sha256: sha256,
  sha512: sha512,
  sha256hmac: sha256hmac,
  aesCbcEncode: aesCbcEncode,
  aesCbcDecode: aesCbcDecode
}

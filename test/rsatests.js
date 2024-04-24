var assert   = require('assert');
var CryptoService = require('../src/crypto/Service');
var opensslUtils = require('../src/openssl/openssl-utils');

// openssl genrsa 512 | openssl pkcs8 -topk8 -nocrypt
var rsa512 = 
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

// echo -n "abcd" | openssl rsautl -encrypt -oaep -inkey rsa512.pem | base64 -w0
var cipher512 = "Xp5uW0NY8bvNJRXS0KSVXXZzMpqdwrWmQrx3f9SArsdBKcGguI030dB8FcIZD6OuGinfRKFDX5NsudI/wHb7xA==";

// echo -n "abcd" | openssl dgst -sha256 -sign rsa512.pem | base64 -w0
var sign512   = "IZSfYu01OGx6PSdWiZpS4oQlMIG9CChkBAbheHinz/l+obezD8b37/9Tj5hUZ+cHtgiwcRXOMe9L7PcLdulniA==";

CryptoService.timeEntropyEnabled = false;

describe('CryptoService', function() {
  it('#rsaGenerateKey', function() {
    return CryptoService.rsaGenerateKey(256).then((key) => {
      var rsa = opensslUtils.parsePem(key);
      assert.equal("PRIVATE KEY", rsa.name);
    });
  });
  it('#rsaOaepEncrypt', function() {
    return CryptoService.rsaOaepEncrypt(rsa512, Buffer.from("abcd")).then((cipher) => {
      assert.equal(cipher.length, 512/8);
    });
  });
  it('#rsaOaepDecrypt', function() {
    return CryptoService.rsaOaepDecrypt(rsa512, Buffer.from(cipher512,'base64')).then((plaintext) => {
      assert.equal(plaintext.toString(), "abcd");
    });
  });
  it('#rsaSign', function() {
    return CryptoService.rsaSign(rsa512, Buffer.from("abcd")).then((signature) => {
      assert.equal(signature.length, 512/8);
    });
  });
  it('#rsaVerify', function() {
    return CryptoService.rsaVerify(rsa512, Buffer.from(sign512,'base64'), Buffer.from("abcd"))
    .then((result) => assert.equal(result, true))
    .then(() => CryptoService.rsaVerify(rsa512, Buffer.from(sign512,'base64'), Buffer.from("abcde")))
    .then((result) => assert.equal(result, false));
  });
});


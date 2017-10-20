module.exports = {
    init: init,
    rsaGenerateKey: rsaGenerateKey,
    rsaDeriveKey:   rsaDeriveKey,
    rsaOaepEncrypt: rsaOaepEncrypt,
    rsaOaepDecrypt: rsaOaepDecrypt,
    rsaSign:        rsaSign,
    rsaVerify:      rsaVerify
}

// will be injected
var service;
function init(_service) {
    service = _service;
}

/**
 * @param {number} bits
 * @returns {Q.Promise<string>} generated PEM encoded private key
 */
function rsaGenerateKey(bits) {
  return genrsa.generateKey(bits, service.randomGenerator());
}

/**
 * @param {number} bits
 * @param {Buffer} seed
 * @returns {Q.Promise<string>} generated PEM encoded private key
 */
function rsaDeriveKey(bits, seed) {
  return genrsa.generateKey(bits, service.randomGenerator(seed));
}


function rsaOaepEncrypt(key, data) {
  return Q().then(() => {
    key = parseKey(key);
    if (!Buffer.isBuffer(data))
      data = Buffer.from(data);
    return oaepEncrypt(key, data);
  });
}

function rsaOaepDecrypt(key, data) {
  return Q().then(() => {
    key = parseKey(key);
    if (!Buffer.isBuffer(data))
      data = Buffer.from(data);
    return oaepDecrypt(key, data);
  });
}

function rsaSign(key, data) {
  return Q().then(() => {
    key = parseKey(key);
    if (!Buffer.isBuffer(data))
      data = Buffer.from(data);
    return sign(key, data);
  });
}

function rsaVerify(key, signature, data) {
  return Q().then(() => {
    key = parseKey(key);
    if (!Buffer.isBuffer(data))
      data = Buffer.from(data);
    return verify(key, signature, data);
  });
}

///// implementation below

var createHash = require("create-hash");
var BN         = require("bn.js").BN;
var parseKey   = require("parse-asn1");
var Q          = require("q");
var genrsa     = require("./genrsa");

/**
 * @param {object} key
 * @param {Buffer} data
 * @return {Buffer}
 */
function encrypt(key, data) {
  var c_size  = key.modulus.byteLength();
  if (data.length > c_size)
    throw new Error("data too long");

  var m = new BN(data);
  if (m.gte(key.modulus))
    throw new Error("data too long");

  var c = new BN(m).toRed(BN.red(key.modulus)).redPow(key.publicExponent).fromRed();
  return c.toArrayLike(Buffer, 'be', c_size);
}

// TODO: Consider adding blending step ... not so important on 
/**
 * @param {object} key
 * @param {Buffer} enc
 * @return {Buffer}
 */
function decrypt(key, enc) {
  var c_size  = key.modulus.byteLength();
  if (enc.length > c_size)
    throw new Error("data too long");

  var c = new BN(enc);
  if (c.gte(key.modulus))
    throw new Error("data too long");

  if (!key.exponent1 || !key.exponent2 || !key.coefficient) {
    var dec = c.toRed(BN.red(key.modulus)).redPow(key.privateExponent).fromRed();
    return dec.toArrayLike(Buffer, 'be', c_size);
  }
  if (!key.pred)
    key.pred = BN.red(key.prime1);
  if (!key.qred)
    key.qred = BN.red(key.prime2);
  var m_1 = c.toRed(key.pred).redPow(key.exponent1); 
  var m_2 = c.toRed(key.qred).redPow(key.exponent2); 
  var h = m_1.sub(m_2);
  if (h.isNeg()) {
    h = h.neg();
    h = h.mul(key.coefficient).mod(key.prime1);
    h = key.prime1.sub(h);
  } else {
    h = h.mul(key.coefficient).mod(key.prime1);
  }
  h = m_2.add(key.prime2.mul(h)); 
  return h.toArrayLike(Buffer, 'be', c_size);
}

function sha1(buffers) {
  if (!Array.isArray(buffers))
    buffers = [buffers];
  var hash = createHash('sha1');
  buffers.forEach(function(buffer) { hash.update(buffer); });
  return hash.digest();
}

function sha256(buffers) {
  if (!Array.isArray(buffers))
    buffers = [buffers];
  var hash = createHash('sha256');
  buffers.forEach(function(buffer) {hash.update(buffer); });
  return hash.digest();
}

function mgf1(seed, len) {
  var outlen = 0;
  var mask = [];
  for(var i = 0; outlen < len; ++i) {
    var ctr = Buffer.alloc(4);
    ctr.writeInt32BE(i);
    var digest = sha1([seed, ctr]);
    mask.push(digest);
    outlen += digest.length;
  }
  return Buffer.concat(mask);
}

function mgf1_xor(seed, data) {
  var len = data.length;
  var outlen = 0;
  for(var i = 0; outlen < len; ++i) {
    var ctr = Buffer.alloc(4);
    ctr.writeInt32BE(i);
    var digest = sha1([seed, ctr]);
    var idx;
    for(idx = 0; idx < digest.length && outlen < len; ++idx, ++outlen) {
      data[outlen] ^= digest[idx];
    }
  }
  return data;
}

function timingSafeEqual(a, b) {
    var equal  = a.length == b.length;
    var length = a.length < b.length ? a.length : b.length;
    for(var i = 0; i < length; ++i)
      equal = equal && (a[i] == b[i]);
    return equal;
}

const oaepEmptyLabelHash = Buffer.from('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'hex');

/**
 * @param {object} key
 * @param {Buffer} data
 * @returns {Buffer}
 */
function oaepEncrypt(key, data) {
  var c_size  = key.modulus.byteLength();
  var md_size = 20; // sha1

  var seed = service.randomBytes(md_size);

  var db = Buffer.alloc(c_size - md_size - 1, 0);
  oaepEmptyLabelHash.copy(db, 0);
  
  data.copy(db, c_size - md_size - 1 - data.length);
  db[c_size - md_size - 1 - data.length - 1] = 1;
 
  mgf1_xor(seed, db);
  mgf1_xor(db, seed);

  var packet = Buffer.concat([Buffer.alloc(1, 0), seed, db]);
  return encrypt(key, packet);
}

function oaepDecrypt(key, data) {
  var mb = decrypt(key, data);
  var good = (mb[0] == 0);

  var md_size = 20; // for sha1 
  var seed = mb.slice(1, 1 + md_size)
  var db   = mb.slice(1 + md_size);

  mgf1_xor(db, seed);
  mgf1_xor(seed, db);

  var labelHash = db.slice(0, md_size);

  var onePos = -1;
  for(var idx = md_size + 1; idx < db.length; ++idx) {
    if (db[idx] == 1 && onePos < 0) {
      onePos = idx;
    }
  }

  if (onePos < 0)
    good = false;

  var expected = oaepEmptyLabelHash;
  if (!timingSafeEqual(labelHash, expected))
    good = false;

  if (!good) 
    throw new Error("Invalid cipher");

  db = db.slice(onePos + 1);
  return db;
}

const pkcs1Prefix  = Buffer.from([0,1]);
const pkcs1Suffix  = Buffer.from([0]);
const sha256Prefix = Buffer.from('3031300d060960864801650304020105000420', 'hex');

function sign(key, data) {
  var c_size  = key.modulus.byteLength();
  var hash    = sha256(data);
  var algInfo = sha256Prefix;
  var pkcs1Infix = Buffer.alloc(c_size - algInfo.length - hash.length - 3, 0xff);
  var packet     = Buffer.concat([pkcs1Prefix, pkcs1Infix, pkcs1Suffix, algInfo, hash]);
  return decrypt(key, packet);
}

function verify(key, signature, data) {
  var c_size  = key.modulus.byteLength();
  var hash    = sha256(data);
  var algInfo = sha256Prefix;

  var encrypted = encrypt(key, signature);
  if (encrypted[0] != 0 || encrypted[1] != 1)
    return false;

  var sigPos = c_size - hash.length - algInfo.length;
  for(var i = 2; i < sigPos - 1; ++i)
    if (encrypted[i] == 0)
      return false;

  if (encrypted[sigPos - 1] != 0)
    return false;

  if (algInfo.compare(encrypted, sigPos, sigPos + algInfo.length) != 0)
    return false;

  return hash.compare(encrypted, sigPos + algInfo.length) == 0; 
}

var Crypto    = require("./Crypto");
var PublicKey = require("./PublicKey");

function ECIES( privateKey, publicKey, opts ) {
  this.privateKey = privateKey;
  this.publicKey = publicKey;
  this.opts = opts || {};
}

ECIES.prototype.getRbuf = function() {
  if (this.rBuf == null) {
    this.rBuf = this.privateKey.getPublicKey().toDER();
  }
  return this.rBuf;
};

ECIES.prototype.getkEkM = function() {
  if (this.kEkM == null) {
    this.kEkM = this.privateKey.getSharedKey(this.publicKey);
  }
  return this.kEkM;
};

ECIES.prototype.getkE = function() {
  if (this.kE == null) {
    this.kE = this.getkEkM().slice(0, 32);
  }
  return this.kE;
};

ECIES.prototype.getkM = function() {
  if (this.kM == null) {
    this.kM = this.getkEkM().slice(32, 64);
  }
  return this.kM;
};

ECIES.prototype.encrypt = function( message, ivbuf ) {
  if (ivbuf === undefined) {
    ivbuf = Crypto.sha256hmac(message, this.privateKey.getPrivateEncKey()).slice(0, 16);
  }
  var c = Buffer.concat([ivbuf, Crypto.aesCbcEncode(message, this.getkE(), ivbuf)]);
  var d = Crypto.sha256hmac(c, this.getkM());
  if(this.opts.shortTag) d = d.slice(0, 4);
  if(this.opts.noKey) {
    var encbuf = Buffer.concat([c, d]);
  } else {
    var encbuf = Buffer.concat([this.getRbuf(), c, d]);
  }
  return encbuf;
};

ECIES.prototype.decrypt = function( encbuf ) {
  var offset = 0;
  var tagLength = 32;
  if(this.opts.shortTag) {
    tagLength = 4;
  }
  if(!this.opts.noKey) {
    offset = 33;
    this.publicKey = PublicKey.fromDER(encbuf.slice(0, 33));
  }

  var c = encbuf.slice(offset, encbuf.length - tagLength);
  var d = encbuf.slice(encbuf.length - tagLength, encbuf.length);

  var d2 = Crypto.sha256hmac(c, this.getkM());
  if(this.opts.shortTag) d2 = d2.slice(0, 4);

  var equal = true;
  for (var i = 0; i < d.length; i++) {
    equal &= (d[i] === d2[i]);
  }
  if (!equal) {
    throw new Error('Invalid checksum');
  }

  return Crypto.aesCbcDecode(c.slice(16), this.getkE(), c.slice(0, 16));
};

module.exports = ECIES;

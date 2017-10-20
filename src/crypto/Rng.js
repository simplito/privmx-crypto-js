var seedrandom = require("seedrandom");
var BN = require("bn.js").BN;

function Rng(seed) {
  if (seed && Buffer.isBuffer(seed))
    seed = seed.toString();
  this.rng = new seedrandom(seed);
}

Rng.prototype.feed = function(value) {
  this.rng = new seedrandom(value, {entropy: true});
}

Rng.prototype.int32 = function() {
  return this.rng.int32();
}

Rng.prototype.double = function() {
  return this.rng.double();
}

Rng.prototype.bytes = function(num) {
  var buffer = new Buffer(num);
  var offset = 0;
  while(num >= 4) {
    buffer.writeInt32LE( this.int32(), offset );
    offset += 4; num -= 4;
  }
  while(num > 0) {
    buffer.writeUInt8( this.int32() & 0xff, offset );
    offset += 1; num -= 1;
  }
  return buffer;
}

Rng.prototype.bits = function(num) {
  var bytes = ((num + 7) / 8) | 0;
  var r = this.bytes(bytes);
  if (num & 7) {
    r[0] >>= 8 - (num & 7);
  }
  return r;
}

Rng.prototype.bn = function(max) {
  if (!BN.isBN(max))
    max = new BN(max);
  var bl = max.byteLength();
  var r  = this.bytes(bl);
  var bn = new BN(r);
  bn.words[bn.length - 1] %= max.words[max.length - 1];
  return bn;
}

module.exports = Rng;

var HDNode        = require("./HDNode");
var BN            = require('bn.js');
var PublicKey     = require('./PublicKey');
var PrivateKey    = require('./PrivateKey');

function ExtKey(key) {
    this.key = key;
}

ExtKey.fromBase58 = function(base58){
    return new ExtKey(HDNode.fromBase58(base58));
};

ExtKey.fromSeed = function(seed) {
    return new ExtKey(HDNode.fromSeedBuffer(seed));
};

ExtKey.generateRandom = function(rng) {
    return ExtKey.generateFromBuffer(rng.bytes(64));
};

ExtKey.generateFromBuffer = function(buffer) {
    return new ExtKey(HDNode.fromRawBuffer(buffer));
};

ExtKey.prototype.isPrivate = function() {
    return !!this.key.privKey
};

ExtKey.prototype.getPrivatePartAsBase58 = function () {
    return this.key.toBase58();
};

ExtKey.prototype.getPublicPartAsBase58 = function() {
    return this.key.neutered().toBase58();
};

ExtKey.prototype.getPublicKey = function() {
    return new PublicKey(this.key.key);
};

ExtKey.prototype.getPrivateKey = function() {
    return new PrivateKey(this.key.key);
};

ExtKey.prototype.getChainCode = function() {
    return this.key.chainCode;
};

ExtKey.prototype.deriveHardened = function(index) {
    return new ExtKey(this.key.deriveHardened(index));
};

ExtKey.deserialize = function(buf){
    var bn = new BN(buf.slice(0, 32).toString('hex'), 16);
    return new ExtKey(
        new HDNode(
            new BN(buf.slice(0, 32).toString('hex'), 16),
            buf.slice(32)
        )
    );
};

ExtKey.prototype.serialize = function(){

    var r = new Buffer(this.key.key.getPrivate('hex'), 'hex');

    if(r.length < 32){
        r = Buffer.concat([
             new Buffer(32 - r.length).fill(0),
             r
        ]);
    }
    return Buffer.concat([
        r,
        new Buffer(this.key.chainCode.toString('hex'), 'hex')
    ]);
};

module.exports = ExtKey;

var elliptic    = require('elliptic');
var ec          = elliptic.ec("secp256k1");
var PublicKey   = require("./PublicKey");
var networks    = require('./networks');
var base58check = require("bs58check");
var assert      = require('assert');
var Crypto      = require("./Crypto");
var BN          = require('bn.js');
var ECIES       = require("./ECIES");

function PrivateKey(key){
    this.key = key;
}

PrivateKey.getSafeBn = function(buffer) {
    if (buffer.length != 32) {
        throw new Error("Expected 32-bytes length buffer");
    }
    var d = new BN(buffer);
    d = d.mod(ec.curve.n.sub(new BN(2)));
    if (d.isZero()) {
        d.iaddn(1);
    }
    return d;
}

PrivateKey.generateRandom = function(rng) {
    return PrivateKey.generateFromBuffer(rng.bytes(32));
};

PrivateKey.generateFromBuffer = function(buffer){
    return new PrivateKey(ec.keyFromPrivate(PrivateKey.getSafeBn(buffer)));
};

PrivateKey.fromWIF = function(wif){
    var payload = base58check.decode(wif);
    var compressed = false;

    payload = payload.slice(1);

    if (payload.length === 33) {
        assert.strictEqual(payload[32], 0x01, 'Invalid compression flag')

        payload = payload.slice(0, -1)
        compressed = true
    }

    assert.equal(payload.length, 32, 'Invalid WIF payload length')
    return new PrivateKey(ec.keyFromPrivate(payload));
};

PrivateKey.prototype.toWIF = function(){
    var network = networks.bitcoin;

    var bufferLen = 34;
    var buffer = new Buffer(bufferLen);

    buffer.writeUInt8(network.wif, 0);
    var b = new Buffer(this.key.getPrivate('hex'), 'hex')
    if(b.length < 32){
        b = Buffer.concat([
             new Buffer(32 - b.length).fill(0),
             b
        ]);
    }

    b.copy(buffer, 1);
    buffer.writeUInt8(0x01, 33);
    return base58check.encode(buffer);
};

PrivateKey.prototype.signToCompactSignature = function(message) {
    var s = this.key.sign(message);

    var i = 27;
    var buffer = new Buffer(65)
    buffer.writeUInt8(i, 0)

    new Buffer(s.r.toArray('be', 32)).copy(buffer, 1)
    new Buffer(s.s.toArray('be', 32)).copy(buffer, 33)

    return buffer;
}

PrivateKey.prototype.getPublicKey = function(){
    return new PublicKey(this.key);
};

PrivateKey.prototype.getPrivateEncKey = function(){
    return this.serialize();
};

PrivateKey.prototype.getSharedKey = function(publicKey){
    var bn = this.key.derive(publicKey.key.getPublic());
    return Crypto.sha512(new Buffer(bn.toArray('be', 32)));
};

PrivateKey.prototype.eciesEncrypt = function(publicKey, data) {
    return new ECIES(this, publicKey, {noKey: true, shortTag: true}).encrypt(data);
}

PrivateKey.prototype.eciesDecrypt = function(publicKey, data) {
    return new ECIES(this, publicKey, {noKey: true, shortTag: true}).decrypt(data);
}

PrivateKey.deserialize = function(buf){
    return new PrivateKey(
        ec.keyFromPrivate(buf)
    );
};

PrivateKey.prototype.serialize = function(){
    var r = new Buffer(this.key.getPrivate('hex'), 'hex');

    if(r.length < 32){
        r = Buffer.concat([
             new Buffer(32 - r.length).fill(0),
             r
        ]);
    }
    return r
};

module.exports = PrivateKey;

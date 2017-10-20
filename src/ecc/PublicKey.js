var elliptic    = require('elliptic');
var base58check = require("bs58check");
var ec          = elliptic.ec("secp256k1");
var Crypto      = require("./Crypto");
var assert      = require('assert');
var networks    = require('./networks');
var BN          = require('bn.js');
var Signature   = require('elliptic/lib/elliptic/ec/signature');

function PublicKey(key){
    this.key = key;
}

PublicKey.fromDER = function(der){
    return this.deserialize(der);
};

PublicKey.prototype.toDER = function(){
    return new Buffer(this.key.getPublic().encodeCompressed());
};

PublicKey.fromBase58DER = function(base58){
    return new PublicKey(ec.keyFromPublic(base58check.decode(base58)));
};

PublicKey.prototype.toBase58DER = function(){
    return base58check.encode(this.toDER());
};

PublicKey.fromHexDER = function(hexDer) {
    return new PublicKey(ec.keyFromPublic(hexDer, 'hex'));
};

PublicKey.prototype.toHexDER = function(){
    return this.key.getPublic().encodeCompressed('hex');
};

PublicKey.prototype.toBase58Address = function(network){
    network = network || networks.bitcoin;

    var hash = Crypto.hash160(new Buffer(this.key.getPublic().encodeCompressed()));
    var version = network.pubKeyHash;

    var payload = new Buffer(21);
    payload.writeUInt8(version, 0);
    hash.copy(payload, 1);
    return base58check.encode(payload);
};

PublicKey.prototype.verifyCompactSignature = function(message, signature){
    assert.equal(signature.length, 65, 'Invalid signature length')
    var i = signature.readUInt8(0) - 27
    assert.equal(i, i & 7, 'Invalid signature parameter')

    var r = new BN(signature.slice(1, 33).toString('hex'), 16);
    var s = new BN(signature.slice(33).toString('hex'), 16);
    var recoveryParam = 1; //??
    var sig = new Signature({ r: r, s: s, recoveryParam: recoveryParam });

    return this.key.verify(message, sig);
}

PublicKey.prototype.equals = function(other) {
    return this.toBase58DER() == other.toBase58DER();
};

PublicKey.deserialize = function(buf){
    return new PublicKey(ec.keyFromPublic(buf));
};

PublicKey.prototype.serialize = function () {
    return new Buffer(
        /*return */this.key.getPublic().encode()
    );
};

module.exports = PublicKey;

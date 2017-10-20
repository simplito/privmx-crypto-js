/**
 * Based on https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/hdnode.js
 */

var networks    = require('./networks');
var typeForce   = require('typeforce');
var assert      = require('assert');
var BN          = require('bn.js');
var elliptic    = require('elliptic');
var base58check = require("bs58check");
var ec          = elliptic.ec("secp256k1");
var PublicKey   = require('./PublicKey');
var PrivateKey  = require('./PrivateKey');
var createHmac  = require('create-hmac');
var crypto      = require("./Crypto")

function findBIP32NetworkByVersion (version) {
    for (var name in networks) {
        var network = networks[name];

        if (version === network.bip32.private || version === network.bip32.public) {
            return network
        }
    }

    assert(false, 'Could not find network for ' + version.toString(16))
}

function HDNode(K, chainCode, network){
    network = network || networks.bitcoin;

    typeForce('Buffer', chainCode)

    assert.equal(chainCode.length, 32, 'Expected chainCode length of 32, got ' + chainCode.length);
    assert(network.bip32, 'Unknown BIP32 constants for network');

    this.chainCode = chainCode
    this.depth = 0
    this.index = 0
    this.parentFingerprint = 0x00000000
    this.network = network

    if (K instanceof BN) {
        this.key = ec.keyFromPrivate(K);
        this.privKey = this.key.getPrivate();
        this.pubKey = this.key.getPublic();
    } else if (K instanceof PrivateKey) {
        this.key = K.key;
        this.privKey = this.key.getPrivate();
        this.pubKey = this.key.getPublic();
    } else if(K instanceof PublicKey){
        this.key = K.key;
        this.pubKey = this.key.getPublic();
    } else {
        throw new Error("not_impelemented");
        // this.pubKey = new ECPubKey(K, true)
    }
};

HDNode.MASTER_SECRET = new Buffer('Bitcoin seed');
HDNode.HIGHEST_BIT = 0x80000000;
HDNode.LENGTH = 78;

HDNode.fromSeedBuffer = function (seed, network) {
  typeForce('Buffer', seed);

  assert(seed.length >= 16, 'Seed should be at least 128 bits');
  assert(seed.length <= 64, 'Seed should be at most 512 bits');

  var I = createHmac('sha512', HDNode.MASTER_SECRET).update(seed).digest();

  return HDNode.fromRawBuffer(I);
};

HDNode.fromRawBuffer = function (buffer, network) {
  typeForce('Buffer', buffer);

  assert(buffer.length == 64, 'Buffer has to be 512 bits');
  
  var key = buffer.slice(0, 32);
  var chaincode = buffer.slice(32);
  
  var bn = PrivateKey.getSafeBn(key);

  return new HDNode(bn, chaincode, network);
};

HDNode.fromBase58 = function(string, network){
    return HDNode.fromBuffer(base58check.decode(string), network);
};

HDNode.fromBuffer = function (buffer, network){
    assert.strictEqual(buffer.length, HDNode.LENGTH, 'Invalid buffer length');

    var version = buffer.readUInt32BE(0)

    if (network) {
        assert(version === network.bip32.private || version === network.bip32.public, "Network doesn't match");
    } else {
        network = findBIP32NetworkByVersion(version);
    }

    var depth = buffer.readUInt8(4);
    var parentFingerprint = buffer.readUInt32BE(5);

    if (depth === 0) {
        assert.strictEqual(parentFingerprint, 0x00000000, 'Invalid parent fingerprint');
    }

    var index = buffer.readUInt32BE(9);
    assert(depth > 0 || index === 0, 'Invalid index');

    var chainCode = buffer.slice(13, 45);
    var data, hd;

    if (version === network.bip32.private) {
        assert.strictEqual(buffer.readUInt8(45), 0x00, 'Invalid private key');
        data = buffer.slice(46, 78);
        var d = new BN(data.toString('hex'), 16);
        hd = new HDNode(d, chainCode, network);
    } else {
        data = buffer.slice(45, 78);
        var Q = ec.curve.decodePoint(data);
        var key = ec.keyPair({pub: Q});
        var pk = new PublicKey(key);

        hd = new HDNode(pk, chainCode, network)
    }

    hd.depth = depth;
    hd.index = index;
    hd.parentFingerprint = parentFingerprint;

    return hd;
};

HDNode.prototype.neutered = function(){
    var neutered = new HDNode(new PublicKey(this.key), this.chainCode, this.network);

    neutered.depth = this.depth;
    neutered.index = this.index;
    neutered.parentFingerprint = this.parentFingerprint;

    return neutered;
};

HDNode.prototype.toBase58 = function(isPrivate){
    return base58check.encode(this.toBuffer(isPrivate))
};

HDNode.prototype.toBuffer = function (isPrivate){
    if (isPrivate === undefined) {
        isPrivate = !!this.privKey;
    } else {
        console.warn('isPrivate flag is deprecated, please use the .neutered() method instead');
    }

    var version = isPrivate ? this.network.bip32.private : this.network.bip32.public;
    var buffer = new Buffer(HDNode.LENGTH);

    buffer.writeUInt32BE(version, 0);
    buffer.writeUInt8(this.depth, 4);
    buffer.writeUInt32BE(this.parentFingerprint, 5);
    buffer.writeUInt32BE(this.index, 9);
    this.chainCode.copy(buffer, 13);

    if (isPrivate) {
        assert(this.privKey, 'Missing private key');
        buffer.writeUInt8(0, 45);
        var r = new Buffer(this.key.getPrivate('hex'), 'hex');
        if (r.length < 32) {
            r = Buffer.concat([new Buffer(32 - r.length).fill(0), r]);
        }
        r.copy(buffer, 46);
    } else {
        var key = this.key.getPublic().encodeCompressed('hex');
        new Buffer(this.key.getPublic().encodeCompressed()).copy(buffer, 45);
    }

    return buffer;
};

HDNode.prototype.getIdentifier = function () {
  return crypto.hash160(new Buffer(this.key.getPublic().encodeCompressed()))
};

HDNode.prototype.getFingerprint = function () {
  return this.getIdentifier().slice(0, 4);
};

HDNode.prototype.derive = function (index) {
    var isHardened = index >= HDNode.HIGHEST_BIT;
    var indexBuffer = new Buffer(4);
    indexBuffer.writeUInt32BE(index, 0);

    var data;

    if (isHardened) {
        assert(this.privKey, 'Could not derive hardened child key');

        data = Buffer.concat([
            new Buffer([0x00]),
            new Buffer(this.key.getPrivate('hex'), 'hex'),
            indexBuffer
        ]);
    } else {

        data = Buffer.concat([
            new Buffer(this.key.getPublic().encodeCompressed()),
            indexBuffer
        ]);
    }

    var I = createHmac('sha512', this.chainCode).update(data).digest();
    var IL = I.slice(0, 32);
    var IR = I.slice(32);

    var pIL = new BN(IL.toString('hex'), 16);

    if (pIL.cmp(ec.curve.n) >= 0) {
        return this.derive(index + 1);
    }

    var hd;
    if (this.privKey) {
        var ki = pIL.add(this.privKey).mod(ec.curve.n)

        if (ki.isZero()) {
            return this.derive(index + 1)
        }

        hd = new HDNode(ki, IR, this.network)


    } else {

        var Ki = ec.curve.G.mul(pIL).add(this.pubKey)


        if (Ki.inf) {
            return this.derive(index + 1)
        }

        hd = new HDNode(Ki, IR, this.network)
    }

    hd.depth = this.depth + 1
    hd.index = index
    hd.parentFingerprint = this.getFingerprint().readUInt32BE(0)

    return hd
};

HDNode.prototype.deriveHardened = function(index){
    return this.derive(index + HDNode.HIGHEST_BIT);
};

HDNode.prototype.toString = HDNode.prototype.toBase58;

module.exports = HDNode;

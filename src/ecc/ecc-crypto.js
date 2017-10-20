module.exports = {
    init: init,
    eccGenerateKey: generateKey,
    ecdsaSign: sign,
    ecdsaVerify: verify,
    eciesEncrypt: eciesEncrypt,
    eciesDecrypt: eciesDecrypt
};

const Q               = require("q");
const crypto          = require("crypto");
const PrivateKey      = require("./PrivateKey");
const PublicKey       = require("./PublicKey");
const elliptic        = require('elliptic');
const ec              = elliptic.ec("secp256k1");
const BN              = require("bn.js");
const oid             = require("../openssl/oid");
const utils           = require("../openssl/openssl-utils");

var CryptoService = null;
function init(service)
{
    var isNode = new Function("try {return this===global;}catch(e){ return false;}");
    if( !isNode() )
    {
        this.ecdsaSign = signBrowser;
        this.ecdsaVerify = verifyBrowser;
    }
    CryptoService = service;
};

// XXX: support only secp256k1
const parameters = utils.asn.ECParameters.encode({
    type: "namedCurve",
    value: oid.idSecp256k1.split(".")
}, "der");

/**
 * Encodes PrivateKey to openssl format
 *
 * @param {PrivateKey} priv
 * @param {string} type - "der" | "pem", default "pem"
 *
 * @return {string|Buffer} - string for "pem", Buffer otherwise
 */
function encodePrivate(priv, type)
{
    var algorithm = {
        algorithm: oid.idEcPublicKey.split("."),
        parameters: parameters
    };

    var key = utils.asn.ECPrivateKey.encode({
        version: 1,
        privateKey: priv.key.getPrivate().toArrayLike(Buffer),
        publicKey: { data: priv.key.getPublic(false, true) }
    }, "der");

    return utils.encodePrivateKey(algorithm, key, type);
};

/**
 * Decodes PrivateKey from openssl format
 *
 * @param {string|Buffer} priv
 *
 * @return {PrivateKey}
 */
function decodePrivate(priv)
{
    var decoded = utils.decodePrivateKey(priv);

    var algorithm = "";
    if( decoded.algorithm && decoded.algorithm.algorithm )
        algorithm = decoded.algorithm.algorithm.join(".");
    if( algorithm !== oid.idEcPublicKey )
        throw new Error("Invalid algorithm (" + algorithm + ")")

    if( !decoded.algorithm.parameters || !parameters.equals(decoded.algorithm.parameters) )
        throw new Error("Invalid parameters");

    if( !decoded.subjectPrivateKey )
        throw new Error("Missing private key data");

    decoded = utils.asn.ECPrivateKey.decode(decoded.subjectPrivateKey);
    if( !decoded.privateKey || !decoded.publicKey )
        throw new Error("Incorrect private key data");

    var key = ec.keyPair({
        pub: decoded.publicKey.data,
        priv: decoded.privateKey
    });

    return new PrivateKey(key);
};

/**
 * Encodes PublicKey to openssl format
 *
 * @param {PublicKey} pub
 * @param {string} type - "der" | "pem", default "pem"
 *
 * @return {string|Buffer} - string for "pem", Buffer otherwise
 */
function encodePublic(pub, type)
{
    var algorithm = {
        algorithm: oid.idEcPublicKey.split("."),
        parameters: parameters
    };

    var key = Buffer.from(pub.key.getPublic(false,true));

    return utils.encodePublicKey(algorithm, key, type);
};

/**
 * Decodes PublicKey from openssl format
 *
 * @param {string|Buffer} pub
 *
 * @return {PublicKey}
 */
function decodePublic(pub)
{
    var decoded = utils.decodePublicKey(pub);

    var algorithm = "";
    if( decoded.algorithm && decoded.algorithm.algorithm )
        algorithm = decoded.algorithm.algorithm.join(".");
    if( algorithm !== oid.idEcPublicKey )
        throw new Error("Invalid algorithm (" + algorithm + ")");

    if( !decoded.algorithm.parameters || !parameters.equals(decoded.algorithm.parameters) )
        throw new Error("Invalid parameters");

    if( !decoded.subjectPublicKey || !decoded.subjectPublicKey.data )
        throw new Error("Missing public key data");

    var key = ec.keyFromPublic(decoded.subjectPublicKey.data);
    return new PublicKey(key);
};

/**
 * Generates random Ecc PrivateKey
 * @param {string} type - "raw" | "pem" | "der", default "pem"
 *
 * @return {Promise<PrivateKey>}
 */
function generateKey(type)
{
    if( typeof(type) === "undefined" )
        type = "pem";

    return Q().then(() => {
        var key = PrivateKey.generateFromBuffer(CryptoService.randomBytes(32));
        if( type === "raw" )
            return key;
        return encodePrivate(key, type);
    });
};

/**
 * Generates ECDSA signature
 *
 * @param {string|Buffer|PrivateKey} priv - ecc private key
 * @param {Buffer} data - data to sign
 *
 * @param {Promise<Buffer>} - ecc signature in DER format
 */
function sign(priv, data)
{
    return Q().then(() => {
        if( priv instanceof PrivateKey )
            priv = encodePrivate(priv, "pem");
        var ctx = crypto.createSign("sha256");
        ctx.update(data);
        return ctx.sign(priv);
    });
};

// Browser polyfill
function signBrowser(priv, data)
{
    return CryptoService.sha256(data).then((hash) => {
        if( !(priv instanceof PrivateKey) )
            priv = decodePrivate(priv);
        var signature = priv.signToCompactSignature(hash);
        return compact2DER(signature);
    });
};

/**
 * Verifies ECDSA signature
 *
 * @param {string|Buffer|PublicKey} pub - ecc public key
 * @param {Buffer} signature
 * @param {Buffer} data
 *
 * @return {Promise<boolean>}
 */
function verify(pub, signature, data)
{
    return Q().then(() => {
        if( isCompact(signature) )
            signature = compact2DER(signature);

        if( pub instanceof PublicKey )
            pub = encodePublic(pub, "pem");
        var ctx = crypto.createVerify("sha256");
        ctx.update(data);
        return ctx.verify(pub, signature);
    });
};

// Browser polyfill
function verifyBrowser(pub, signature, data)
{
    return CryptoService.sha256(data).then((hash) => {
        if( !(pub instanceof PublicKey) )
            pub = decodePublic(pub);
        if( !isCompact(signature) )
            signature = DER2compact(signature);
        return pub.verifyCompactSignature(hash, signature);
    });
};

/**
 * Extracts PublicKey from PrivateKey
 *
 * @param {string|Buffer} priv
 *
 * @return {Promise<string>}
 */
function extractPublicKey(priv)
{
    var openssl = require("../openssl/openssl-handler");
    return openssl.extractPublicKey(priv);
};

/**
 * ECIES encryption
 *
 * @param {string|Buffer|PrivateKey} priv
 * @param {string|Buffer|PublicKey} pub
 * @param {Buffer} data
 *
 * @return {Promise<Buffer>}
 */
function eciesEncrypt(priv, pub, data)
{
    return Q().then(() => {
        if( !(priv instanceof PrivateKey) )
            priv = decodePrivate(priv);
        if( !(pub instanceof PublicKey) )
            pub = decodePublic(pub);

        return priv.eciesEncrypt(pub, data);
    });
};

/**
 * ECIES decryption
 *
 * @param {string|Buffer|PrivateKey} priv
 * @param {string|Buffer|PublicKey} pub
 * @param {Buffer} data
 *
 * @return {Promise<Buffer>}
 */
function eciesDecrypt(priv, pub, data)
{
    return Q().then(() => {
        if( !(priv instanceof PrivateKey) )
            priv = decodePrivate(priv);
        if( !(pub instanceof PublicKey) )
            pub = decodePublic(pub);

        return priv.eciesDecrypt(pub, data);
    });
};

function isCompact(sign) {
    return sign.readUInt8(0) === 0x1B && sign.length === 65;
}

/**
 * Converts ecc signature from compact format to DER
 *
 * @param {Buffer} sign
 *
 * @param {Buffer}
 */
function compact2DER(sign)
{
    if( !isCompact(sign) )
        throw new Error("Unknown signature format");

    var data = {
        r: new BN(sign.slice(1, 33)),
        s: new BN(sign.slice(33))
    };

    return utils.asn.signature.encode(data, "der");
};

/**
 * Converts ecc signature from DER format to compact
 *
 * @param {Buffer} sign
 *
 * @param {Buffer}
 */
function DER2compact(sign)
{
    var data = utils.asn.signature.decode(sign);
    return Buffer.concat([
        Buffer.from([0x1B]),
        Buffer.from(data.r.toArray('be', 32)),
        Buffer(data.s.toArray('be', 32))
    ]);
};

module.exports = {
    init: init,
    encryptPrivateKey: encryptKey,
    decryptPrivateKey: decryptKey,
    extractPublicKey: extractPublic
};

const Q = require("q");
const oid = require("./oid");
const utils = require("./openssl-utils");

var service;
function init(_service) {
  service = _service;
}

/**
 * Encrypt private key with passphrase
 *
 * @param {string|Buffer} key - private key in DER or PEM format
 * @param {string} passphrase
 *
 * @return {Promise<string>}
 */
function encryptKey(key, passphrase) {
    if( !utils.isDER(key) )
    {
        var pem = utils.parsePem(key);
        if( !pem || pem.name !== "PRIVATE KEY" )
            return Q.reject(new Error("Invalid argument"));
        key = pem.data;
    }

    var rand  = service.randomBytes(32);
    var salt  = rand.slice(0, 16);
    var iv    = rand.slice(16);
    var iters = 4096;
    return service.pbkdf2(passphrase, salt, iters, 32, 'sha1')
    .then((cek) => {
        return service.aes256CbcPkcs7Encrypt(key, cek, iv);
    })
    .then((cipherText) => {
        var epk = {
            algorithm: {
                id: oid.idPBES2.split('.'),
                decrypt: {
                    kde: {
                        id: oid.idPBKDF2.split('.'),
                        kdeparams: {
                            salt: salt,
                            iters: iters
                        }
                    },
                    cipher: {
                        algo: oid.idAES256CBC.split('.'),
                        iv: iv
                    }
                },
            },
            subjectPrivateKey: cipherText
        };
        return utils.asn.EncryptedPrivateKey.encode(epk, 'pem', {label: "ENCRYPTED PRIVATE KEY"});
    });
};

/**
 * Decrypt private key with passphrase
 *
 * @param {string|Buffer} key - private encrypted key in DER or PEM format
 * @param {string} passphrase
 *
 * @return {Promise<string>}
 */
function decryptKey(key, passphrase) {
    if( !utils.isDER(key) )
    {
        var pem = utils.parsePem(key);
        if (!pem || pem.name !== "ENCRYPTED PRIVATE KEY")
            return Q.reject(new Error("Invalid argument"));
        key = pem.data;
    }

    return Q().then(() => {
        var epk = utils.asn.EncryptedPrivateKey.decode(key);

        var algo = epk.algorithm.id.join('.');
        if (algo !== oid.idPBES2)
            throw new Error("unsupported encrypted key algorithm " + algo);

        var kde = epk.algorithm.decrypt.kde.id.join('.');
        if (kde !== oid.idPBKDF2)
            throw new Error("unsupported encrypted key derivation algorithm " + kde);

        var cipher = epk.algorithm.decrypt.cipher.algo.join('.');
        if (cipher !== oid.idAES256CBC)
            throw new Error("unsupported encrypted key cipher " + cipher);

        var kdeparams = epk.algorithm.decrypt.kde.kdeparams;
        var salt  = kdeparams.salt;
        var iters = kdeparams.iters.toNumber();

        return service.pbkdf2(passphrase, salt, iters, 32, 'sha1')
        .then((key) => {
            var iv = epk.algorithm.decrypt.cipher.iv;
            return service.aes256CbcPkcs7Decrypt(epk.subjectPrivateKey, key, iv);
        })
        .then((key) => {
            return "-----BEGIN PRIVATE KEY-----\n" + utils.chunk(key.toString('base64'), 64) + "-----END PRIVATE KEY-----";
        });
    });
};

/**
 * Extract Public Key from Private Key
 *
 * @param {string|Buffer} priv - private key in DER or PEM format
 *
 * @return {Promise<string>}
 */
function extractPublic(priv) {
    return Q().then(function() {
        var pk = utils.decodePrivateKey(priv);
        var algorithm = pk.algorithm.algorithm.join('.');
        var pub = null;

        switch(algorithm)
        {
            case oid.idrsaEncryption:
                var rsa = utils.asn.RSAPrivateKey.decode(pk.subjectPrivateKey);
                pub = utils.asn.RSAPublicKey.encode(rsa);
                break;
            case oid.idEcPublicKey:
                var ecc = utils.asn.ECPrivateKey.decode(pk.subjectPrivateKey);
                pub = ecc.publicKey.data;
                break;
            default:
                throw new Error("unsupported pki algorithm " + algorithm);
        }

        return utils.encodePublicKey(pk.algorithm, pub, "pem");
    });
};

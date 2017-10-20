const asn = require("./asn1");

module.exports = {
    asn: asn,
    isDER: isDER,
    parsePem: parsePem,
    chunk: chunk,
    encodePrivateKey: encodePrivate,
    decodePrivateKey: decodePrivate,
    encodePublicKey: encodePublic,
    decodePublicKey: decodePublic
};

function chunk(str, len) {
  if (str.length == 0)
    return "";
  return str.slice(0, len) + "\n" + chunk(str.slice(len), len);
}

/**
 * @param   {string|Buffer} pem
 * @returns {false|{name:string,data:Buffer}}  
 */
function parsePem(pem) {
  if (Buffer.isBuffer(pem))
    pem = pem.toString();
  var m = pem.match(/\s*-----BEGIN ([^-]+)-----\s+((.|\s)*)\s+-----END (\1)-----/m);
  if (!m)
    return m;
  return { name: m[1], data: Buffer.from(m[2], "base64") }; 
}

/**
 * @param {string|Buffer} key
 *
 * @return {boolean}
 */
function isDER(key) {
    return Buffer.isBuffer(key) && key[0] === 0x30;
};

/**
 * Encodes PrivateKey to openssl format
 *
 * @param {object} algorithm
 * @param {Buffer} priv
 * @param {string} type - "der" | "pem", default "pem"
 *
 * @return {string|Buffer} - string for "pem", Buffer otherwise
 */
function encodePrivate(algorithm, priv, type)
{
    if( typeof(type) === "undefined" )
        type = "pem";

    var data = {
        version: 0,
        algorithm: algorithm,
        subjectPrivateKey: priv
    };

    if( type === "pem" )
        return asn.PrivateKey.encode(data, "pem", {label: "PRIVATE KEY"});
    return asn.PrivateKey.encode(data, "der");
};

/**
 * Decodes PrivateKey from openssl format
 *
 * @param {string|Buffer} priv
 *
 * @return {object}
 */
function decodePrivate(priv)
{
    if( !isDER(priv) )
    {
        var pem = parsePem(priv);
        if( !pem || pem.name !== "PRIVATE KEY" )
            throw new Error("Invalid argument");
        priv = pem.data;
    }

    return asn.PrivateKey.decode(priv);
};

/**
 * Encodes PublicKey to openssl format
 *
 * @param {object} algorithm
 * @param {Buffer} pub
 * @param {string} type - "der" | "pem", default "pem"
 *
 * @return {string|Buffer} - string for "pem", Buffer otherwise
 */
function encodePublic(algorithm, pub, type)
{
    if( typeof(type) === "undefined" )
        type = "pem";

    var data = {
        algorithm: algorithm,
        subjectPublicKey: { data: pub }
    };

    if( type === "pem" )
        return asn.PublicKey.encode(data, "pem", {label: "PUBLIC KEY"});
    return asn.PublicKey.encode(data, "der");
};

/**
 * Decodes PublicKey from openssl format
 *
 * @param {string|Buffer} pub
 *
 * @return {object}
 */
function decodePublic(pub)
{
    if( !isDER(pub) )
    {
        var pem = parsePem(pub);
        if( !pem || pem.name  !== "PUBLIC KEY" )
            throw new Error("Invalid argument");
        pub = pem.data;
    }

    return asn.PublicKey.decode(pub);
};

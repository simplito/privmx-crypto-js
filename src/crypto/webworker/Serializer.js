var BrowserBuffer = require("../../browserbuffer/BrowserBuffer");
var Ecc = require("../../ecc");

/**
 * Serializer
 * @class
 */
function Serializer() {
}

/**
 * Recursively encodes value
 * @param {any} value
 * @return {any}
 */
Serializer.prototype.encode = function(value) {
    // primitives
    if( typeof(value) !== "object" )
        return value;

    // array
    if( Array.isArray(value) )
        return value.map((v) => this.encode(v));

    // buffer
    if( value instanceof Buffer || value instanceof ArrayBuffer || value instanceof Uint8Array )
    {
        return {
            _type: "buffer",
            _value: BrowserBuffer.bufferToArray(value, false)
        };
    }

    var type = "";
    if( value instanceof Ecc.PublicKey )
        type = "eccpub";
    else if( value instanceof Ecc.PrivateKey )
        type = "eccpriv";
    else if( value instanceof Ecc.ExtKey )
        type = "eccext";

    // ecc keys
    if( type !== "" )
    {
        return {
            _type: type,
            _value: BrowserBuffer.bufferToArray(value.serialize(), false)
        };
    }

    // object
    var res = {};
    for(var key in value)
        res[key] = this.encode(value[key]);
    return res;
};

/**
 * Recursively decodes value
 * @param {any} value
 * @return {any}
 */
Serializer.prototype.decode = function(value) {
    // primitives
    if( typeof(value) !== "object" )
        return value;

    // array
    if( Array.isArray(value) )
        return value.map((v) => this.decode(v));

    // encoded object
    if( value._type && value._value && Object.keys(value).length === 2 )
    {
        switch(value._type)
        {
            case "buffer":
                return BrowserBuffer.arrayToBuffer(value._value);
            case "eccpub":
                return Ecc.PublicKey.deserialize(BrowserBuffer.arrayToBuffer(value._value));
            case "eccpriv":
                return Ecc.PrivateKey.deserialize(BrowserBuffer.arrayToBuffer(value._value));
            case "eccext":
                return Ecc.ExtKey.deserialize(BrowserBuffer.arrayToBuffer(value._value));
        }
        throw new Error("Invalid type " + type);
    }

    // object
    var res = {};
    for(var key in value)
        res[key] = this.decode(value[key]);
    return res;
};

module.exports = new Serializer();
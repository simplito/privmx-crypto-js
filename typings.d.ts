import crypto = require("./src/crypto");
import ecc = require("./src/ecc");
import utils = require("./src/utils");

export let service: crypto.ServiceType;

export {
    crypto,
    ecc,
    utils
};

export class browserbuffer {
    static bufferToArray(buffer: Buffer, copy?: boolean): ArrayBuffer;
    static arrayToBuffer(buffer: ArrayBuffer): Buffer;
    static isBuffer(buffer: any): boolean;
    static createBlob(buffer: Buffer, mimetype: string): Blob;
}

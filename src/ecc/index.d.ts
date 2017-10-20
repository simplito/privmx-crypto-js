import elliptic = require("elliptic");

export class PublicKey {
    
    key: elliptic.ec.KeyPair;
    
    constructor(key: elliptic.ec.KeyPair);
    
    static fromDER(der: Buffer): PublicKey;
    static fromBase58DER(base58: string): PublicKey;
    static fromHexDER(hexDer: string): PublicKey;
    static deserialize(buf: Buffer): PublicKey;
    
    toDER(): Buffer;
    toBase58DER(): string;
    toHexDER(): string;
    serialize(): Buffer;
    
    toBase58Address(network: number): string;
    verifyCompactSignature(message: Buffer, signature: Buffer): boolean;
    equals(other: PublicKey): boolean;
}

export class PrivateKey {
    
    key: elliptic.ec.KeyPair;
    
    constructor(key: elliptic.ec.KeyPair);
    
    static generateRandom(): PrivateKey;
    static generateFromBuffer(buffer: Buffer): PrivateKey;
    static fromWIF(wif: string): PrivateKey;
    
    toWIF(): string;
    signToCompactSignature(message: Buffer): Buffer;
    getPublicKey(): PublicKey;
    getPrivateEncKey(): Buffer;
    getSharedKey(publicKey: PublicKey): Buffer;
    eciesEncrypt(publicKey: PublicKey, data: Buffer): ECIES;
    eciesDecrypt(publicKey: PublicKey, data: Buffer): ECIES;
    deserialize(buf: Buffer): PrivateKey;
    serialize(): Buffer;
}

export interface ECIESOptions {
  shortTag?: boolean;
  noKey?: boolean;
}

export class ECIES {
    
    privateKey: PrivateKey;
    publicKey: PublicKey;
    opts: ECIESOptions;
    
    constructor(privateKey: PrivateKey, publicKey: PublicKey, opts?: ECIESOptions);
    getRbuf(): Buffer;
    getkEkM(): Buffer;
    getkE(): Buffer;
    getkM(): Buffer;
    encrypt(message: Buffer, ivbuf: Buffer): Buffer;
    decrypt(encbuf: Buffer): Buffer;
}

export interface HDNode {
    key: elliptic.ec.KeyPair;
}

export class ExtKey {
    
    key: HDNode;
    
    constructor(key: HDNode);
    
    static fromBase58(base58: string): ExtKey;
    static fromMnemonic(mnemonic: string): ExtKey;
    static fromRandom(random: Buffer): ExtKey;
    static fromSeed(seed: Buffer): ExtKey;
    isPrivate(): boolean;
    static generateRandom(): ExtKey;
    getPrivatePartAsBase58(): string;
    getPublicPartAsBase58(): string;
    getPublicKey(): PublicKey;
    getPrivateKey(): PrivateKey;
    getChainCode(): Buffer;
    deriveHardened(index: number): ExtKey;
    deserialize(buf: Buffer): ExtKey;
    serialize(): Buffer;
}

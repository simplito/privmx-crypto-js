import ecc = require("../ecc");
import utils = require("../utils");
import Q = require("q");
import BN = require("bn.js");

export interface Rng {
    feed(seed: Buffer): void;
    int32(): number;
    double(): number;
    bytes(num: number): Buffer;
    bits(num: number): Buffer;
    bn(max: BN): BN;
}

export interface ServiceType {
    writeEntropy(buffer: Buffer): void;
    startEntropy(): void;
    feed(consumer: {randomFeed(data: Buffer): any}|{execute(method: string, args: any[]): any}): void;
    init(path: string): void
    execute(method: string, params: any): Q.Promise<any>;
    randomGenerator(seed?: Buffer): Rng;
    randomFeed(seed: Buffer): void;
    randomInt32(): number;
    randomDouble(): number;
    randomBytes(num: number): Buffer;
    randomBits(num: number): Buffer;
    randomBN(max: BN): BN;
    hmacSha1(key: Buffer, data: Buffer): Q.Promise<Buffer>
    hmacSha256(key: Buffer, data: Buffer): Q.Promise<Buffer>
    hmacSha256Sync(key: Buffer, data: Buffer): Buffer
    hmacSha512(key: Buffer, data: Buffer): Q.Promise<Buffer>
    sha1(data: Buffer): Q.Promise<Buffer>
    sha256(data: Buffer): Q.Promise<Buffer>
    sha512(data: Buffer): Q.Promise<Buffer>
    aes256CbcPkcs7Encrypt(data: Buffer, key: Buffer, iv: Buffer): Q.Promise<Buffer>
    aes256CbcPkcs7Decrypt(data: Buffer, key: Buffer, iv: Buffer): Q.Promise<Buffer>
    xteaEcbPkcs7Encrypt(data: Buffer, key: Buffer): Q.Promise<Buffer>
    xteaEcbPkcs7Decrypt(data: Buffer, key: Buffer): Q.Promise<Buffer>
    prf_tls12(key: Buffer, seed: Buffer, length: number): Q.Promise<Buffer>
    hkdfSha256(key: Buffer, salt: Buffer, length: number): Q.Promise<Buffer>
    aes256CbcHmac256Encrypt(data: Buffer, key32: Buffer, deterministic: boolean, taglen: number): Q.Promise<Buffer>
    aes256CbcHmac256Decrypt(data: Buffer, key32: Buffer, taglen: number): Q.Promise<Buffer>
    aes256Ecb(data: Buffer, key: Buffer): Q.Promise<Buffer>
    aes256EcbSync(data: Buffer, key: Buffer): Buffer
    aes256EcbDecrypt(data: Buffer, key: Buffer): Q.Promise<Buffer>
    aes256EcbDecryptSync(data: Buffer, key: Buffer): Buffer
    privmxEncrypt(data: Buffer, key: Buffer, iv?: Buffer): Q.Promise<Buffer>
    privmxEncrypt(options: PrivmxEncryptOptions, data: Buffer, key: Buffer, iv?: Buffer): Q.Promise<Buffer>
    privmxDecrypt(data: Buffer, key: Buffer, iv?: Buffer): Q.Promise<Buffer>
    privmxDecrypt(options: PrivmxDcryptOptions, data: Buffer, key: Buffer, iv?: Buffer): Q.Promise<Buffer>
    privmxGetBlockSize(options: PrivmxEncryptOptions, blockSize: number): number;
    privmxHasSignature(data: Buffer|number): boolean;
    privmxSetErrorOnMissingSignature(value: boolean): void;
    privmxOptAesWithDettachedIv(): PrivmxEncryptOptions;
    privmxOptAesWithAttachedIv(): PrivmxEncryptOptions;
    privmxOptAesWithSignature(): PrivmxEncryptOptions;
    privmxOptXtea(): PrivmxEncryptOptions;
    privmxOptSignedCipher(): PrivmxDcryptOptions;
    generateIv(key: Buffer, idx: number): Q.Promise<Buffer>
    reductKey(key: Buffer): Q.Promise<Buffer>
    aesEncryptWithDetachedIv(data: Buffer, key: Buffer, iv: Buffer): Q.Promise<Buffer>
    aesEncryptWithAttachedIv(data: Buffer, key: Buffer, iv: Buffer): Q.Promise<Buffer>
    aesEncryptWithAttachedRandomIv(data: Buffer, key: Buffer): Q.Promise<Buffer>
    xteaEncrypt(data: Buffer, key: Buffer): Q.Promise<Buffer>
    xteaEncrypt32(data: Buffer, key32: Buffer): Q.Promise<Buffer>
    decrypt(data: Buffer, key32?: Buffer, iv16?: Buffer, paramGetter?: utils.LazyMapGetter): Q.Promise<Buffer>
    pbkdf2(password: Buffer, salt: Buffer, rounds: number, length: number, algorithm: string): Q.Promise<Buffer>
    signToCompactSignature(priv: ecc.PrivateKey, hash: Buffer): Q.Promise<Buffer>
    signToCompactSignatureWithHash(priv: ecc.PrivateKey, message: Buffer): Q.Promise<Buffer>
    getSharedKey(priv: ecc.PrivateKey, pub: ecc.PublicKey): Q.Promise<Buffer>
    eciesEncrypt(priv: ecc.PrivateKey, pub: ecc.PublicKey, data: Buffer): Q.Promise<Buffer>
    eciesDecrypt(priv: ecc.PrivateKey, pub: ecc.PublicKey, data: Buffer): Q.Promise<Buffer>
    verifyCompactSignature(pub: ecc.PublicKey, hash: Buffer, signature: Buffer): Q.Promise<boolean>
    verifyCompactSignatureWithHash(pub: ecc.PublicKey, message: Buffer, signature: Buffer): Q.Promise<boolean>
    deriveHardened(ext: ecc.ExtKey, idx: number): Q.Promise<ecc.ExtKey>
    eccGenerateKey(enc: "raw"): Q.Promise<ecc.PrivateKey>;
    eccGenerateKey(enc: "pem"|"der"): Q.Promise<string>;
    ecdsaSign(priv: ecc.PrivateKey|Buffer|string, data: Buffer): Q.Promise<Buffer>;
    ecdsaVerify(pub: ecc.PublicKey|Buffer|string, signature: Buffer, data: Buffer): Q.Promise<Buffer>;
    bip39Generate(strength: number, password?: string): Q.Promise<Bip39>
    bip39FromEntropy(entropy: Buffer, password?: string): Q.Promise<Bip39>
    bip39FromMnemonic(mnemonic: string, password?: string): Q.Promise<Bip39>
    bip39GetExtKey(mnemonic: string, password?: string): Q.Promise<ecc.ExtKey>
    srpRegister(N: Buffer, g: Buffer, I: string, P: string): Q.Promise<{s: Buffer, v: Buffer}>
    srpLoginStep1(N: Buffer, g: Buffer, s: Buffer, B: Buffer, k: Buffer, I: string, P: string): Q.Promise<{A: Buffer, K: Buffer, M1: Buffer, M2: Buffer}>
    srpLoginStep2(clientM2: Buffer, serverM2: Buffer): Q.Promise<void>
    rsaGenerateKey(bits: number): Q.Promise<string>;
    rsaOaepEncrypt(key: string, data: Buffer): Q.Promise<Buffer>;
    rsaOaepDecrypt(key: string, data: Buffer): Q.Promise<Buffer>;
    rsaSign(key: string, data: Buffer): Q.Promise<Buffer>;
    rsaVerify(key: string, signature: Buffer, data: Buffer): Q.Promise<Buffer>;
    encryptPrivateKey(key: string, passphrase: string): Q.Promise<string>;
    decryptPrivateKey(enckey: string, passphrase: string): Q.Promise<string>;
    extractPublicKey(priv: string|Buffer): Q.Promise<string>;
}

export let Service: ServiceType;

export interface PrivmxEncryptTypes {
    AES_256_CBC_PKC7_NO_IV: number
    AES_256_CBC_PKC7_WITH_IV: number
    XTEA_ECB: number
    AES_256_CBC_PKC7_WITH_IV_AND_HMAC_SHA256: number
}

export interface PrivmxEncryptOptions {
    algorithm?: string;
    attachIv?: boolean;
    hmac?: string;
    deterministic?: boolean;
    taglen?: number;
}

export interface PrivmxDcryptOptions {
    signed?: boolean;
    taglen?: number;
}

export interface CryptoType {
    hmacSha1(key: Buffer, data: Buffer): Buffer
    hmacSha256(key: Buffer, data: Buffer): Buffer
    hmacSha512(key: Buffer, data: Buffer): Buffer
    sha1(data: Buffer): Buffer
    sha256(data: Buffer): Buffer
    sha512(data: Buffer): Buffer
    aes256CbcPkcs7Encrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer
    aes256CbcNoPadEncrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer
    aes256CbcPkcs7Decrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer
    aes256CbcNoPadDecrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer
    xteaEcbPkcs7Encrypt(data: Buffer, key: Buffer): Buffer
    xteaEcbPkcs7Decrypt(data: Buffer, key: Buffer): Buffer
    kdf(algo: string, length: number, key: Buffer, options: {}|string): Buffer
    getKEM(algo: string, key: Buffer, kelen: number, kmlen: number): Buffer[]
    aes256CbcHmac256Encrypt(data: Buffer, key32: Buffer, deterministic: boolean, taglen: number): Buffer
    aes256CbcHmac256Decrypt(data: Buffer, key32: Buffer, taglen: number): Buffer
    prf_tls12(key: Buffer, seed: Buffer, length: number): Buffer
    aes256Ecb(data: Buffer, key: Buffer): Buffer
    aes256EcbDecrypt(data: Buffer, key: Buffer): Buffer
    TYPES: PrivmxEncryptTypes
    bufferFromInt(int: number): Buffer;
    generateIv(key: Buffer, idx: number): Buffer;
    reductKey(key: Buffer): Buffer;
    aesEncryptWithDetachedIv(data: Buffer, key: Buffer, iv: Buffer): Buffer;
    aesEncryptWithAttachedIv(data: Buffer, key: Buffer, iv: Buffer): Buffer;
    aesEncryptWithAttachedRandomIv(data: Buffer, key: Buffer): Buffer;
    xteaEncrypt(data: Buffer, key: Buffer): Buffer;
    xteaEncrypt32(data: Buffer, key32: Buffer): Buffer;
    defaultParamGetter<T>(map: utils.LazyMap, name: string): T;
    createParamsLazyMap(key32?: Buffer, iv16?: Buffer, paramGetter?: utils.LazyMapGetter): utils.LazyMap;
    decrypt(data: Buffer, key32?: Buffer, iv16?: Buffer, paramGetter?: utils.LazyMapGetter): Buffer;
    pbkdf2(password: Buffer, salt: Buffer, rounds: number, length: number, algorithm: string): Buffer;
    signToCompactSignature(priv: ecc.PrivateKey, hash: Buffer): Buffer;
    signToCompactSignatureWithHash(priv: ecc.PrivateKey, message: Buffer): Buffer;
    getSharedKey(priv: ecc.PrivateKey, pub: ecc.PublicKey): Buffer;
    verifyCompactSignature(pub: ecc.PublicKey, hash: Buffer, signature: Buffer): boolean;
    verifyCompactSignatureWithHash(pub: ecc.PublicKey, message: Buffer, signature: Buffer): boolean;
    deriveHardened(ext: ecc.ExtKey, idx: number): ecc.ExtKey;
    bip39FromEntropy(entropy: Buffer, password?: string): Bip39;
    bip39FromMnemonic(mnemonic: string, password?: string): Bip39;
    bip39GetExtKey(mnemonic: string, password?: string): ecc.ExtKey;
    srpRegister(N: Buffer, g: Buffer, I: string, P: string, s: Buffer): {s: Buffer, v: Buffer};
    srpLoginStep1(N: Buffer, g: Buffer, s: Buffer, B: Buffer, k: Buffer, I: string, P: string, a: Buffer): {A: Buffer, K: Buffer, M1: Buffer, M2: Buffer};
    srpLoginStep2(clientM2: Buffer, serverM2: Buffer): void;
}

export let Crypto: CryptoType;

export interface PasswordMixerData {
    algorithm: string;
    hash: string;
    length: number;
    rounds: number;
    salt: Buffer;
    version: number;
}

export interface LoginData {
    mixed: Buffer;
    data: PasswordMixerData;
}

export interface PasswordMixerType {
    serializeData(data: PasswordMixerData): string;
    deserializeData(raw: string): PasswordMixerData;
    generatePbkdf2(password: string): Q.Promise<LoginData>;
    mix(password: string, data: PasswordMixerData): Q.Promise<Buffer>;
    perform(password: string, data: PasswordMixerData): Q.Promise<Buffer>;
}

export let PasswordMixer: PasswordMixerType;

export interface Bip39 {
    extKey: ecc.ExtKey
    entropy: Buffer
    mnemonic: string
}

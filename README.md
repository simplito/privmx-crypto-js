

# PrivMX Crypto Java Script ....

## Information

...

Keywords: Hash HMAC AES XTEA RSA KeyDerivation ECC BIP39 SRP Random ...

This software is licensed under the MIT License.

Projects which use the library: [PrivMX WebMail](https://privmx.com), ...


## Installation

...



## Implementation details


...



## API description

### Hash functions

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| sha1 | SHA-1 (20 bytes long) | Buffer data | Promise&lt;Buffer&gt;
| sha256 | SHA-256 (32 bytes long) | Buffer data | Promise&lt;Buffer&gt;
| sha512 | SHA-512 (64 bytes long) | Buffer data | Promise&lt;Buffer&gt;

### Hmac functions

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| hmacSha1 | HMAC-SHA-1 | Buffer key<br />Buffer data | Promise&lt;Buffer&gt; |
| hmacSha256 | HMAC-SHA-256 | Buffer key<br />Buffer data | Promise&lt;Buffer&gt; |
| hmacSha512 | HMAC-SHA-512 | Buffer key<br />Buffer data | Promise&lt;Buffer&gt; |

### AES encryption

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| aes256Ecb | AES-256-ECB | Buffer data<br />Buffer key | Promise&lt;Buffer&gt; |
| aes256EcbDecrypt | AES-256-ECB | Buffer data<br />Buffer key | Promise&lt;Buffer&gt; |
| aes256CbcPcks7Encrypt | AES-256-CBC with PKCS7 padding encryption | Buffer data<br />Buffer key<br />Buffer iv | Promise&lt;Buffer&gt; |
| aes256CbcPcks7Decrypt | AES-256-CBC with PKCS7 padding decryption | Buffer data<br />Buffer key<br />Buffer iv | Promise&lt;Buffer&gt; |
| aes256CbcHmac256Encrypt | AES-256-CBC with PKCS7 padding and SHA-256 HMAC with NIST compatible KDF | Buffer data<br />Buffer key<br />bool deterministic, default: false<br />number taglen, default: 16 | Promise&lt;Buffer&gt; |
| aes256CbcHmac256Decrypt | AES-256-CBC with PKCS7 padding and SHA-256 HMAC with NIST compatible KDF | Buffer data<br />Buffer key<br />number taglen, default: 16 | Promise&lt;Buffer&gt; |

### XTEA encryption

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| xteaEcbPkcs7Encrypt | XTEA-ECB with PKCS7 padding encryption | Buffer data<br />Buffer key | Promise&lt;Buffer&gt; |
| xteaEcbPkcs7Decrypt | XTEA-ECB with PKCS7 padding decryption | Buffer data<br />Buffer key | Promise&lt;Buffer&gt; |

### RSA encryption

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| rsaGenerateKey | | number bits | Promise&lt;string&gt; |
| rsaOaepEncrypt | | string key<br />Buffer data | Promise&lt;Buffer&gt; |
| rsaOaepDecrypt | | string key<br />Buffer data | Promise&lt;Buffer&gt; |
| rsaSign | | string key<br />Buffer data | Promise&lt;Buffer&gt; |
| rsaVerify | | string key<br />Buffer signature<br />Buffer data | Promise&lt;boolean&gt; |
| encryptPrivateKey | | string key<br />string passphrase | Promise&lt;string&gt; |
| decryptPrivateKey | | string enckey<br />string passphrase | Promise&lt;string&gt; |

### Key derivation

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| pbkdf2 | | string password<br />Buffer salt<br />number rounds<br />number length<br />string algorithm | Promise&lt;Buffer&gt; |
| prf_tls12 | | Buffer key<br />Buffer seed<br />number length | Promise&lt;Buffer&gt; |

### ECC functions

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| signToCompactSignature | | Ecc.PrivateKey key<br />Buffer message | Promise&lt;Buffer&gt; |
| verifyCompactSignature | | Ecc.PublicKey key<br />Buffer data<br />Buffer signature | Promise&lt;bool&gt; |
| signToCompactSignatureWithHash | | Ecc.PrivateKey key<br />Buffer message | Promise&lt;Buffer&gt; |
| verifyCompactSignatureWithHash | | Ecc.PublicKey key<br />Buffer data<br />Buffer signature | Promise&lt;bool&gt; |
| getSharedKey | | Ecc.PrivateKey private<br />Ecc.PublicKey public | Promise&lt;Buffer&gt; |
| deriveHardened | | Ecc.ExtKey key<br />number index | Promise&lt;Ecc.ExtKey&gt; |
| eciesEncrypt | | Ecc.PrivateKey private<br />Ecc.PublicKey public<br />Buffer data | Promise&lt;Buffer&gt; |
| eciesDecrypt | | Ecc.PrivateKey private<br />Ecc.PublicKey public<br />Buffer data | Promise&lt;Buffer&gt; |

### BIP39 functions

```javascript
interface Bip39Result {
    entropy: Buffer;
    mnemonic: Buffer;
    extKey: Ecc.ExtKey;
};
```

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| bip39Generate | | number strength<br />string password | Promise&lt;Bip39Result&gt; |
| bip39FromEntropy | | Buffer entropy<br />string password | Promise&lt;Bip39Result&gt; |
| bip39FromMnemonic | | Buffer entropy<br />string password | Promise&lt;Bip39Result&gt; |
| bip39GetExtKey | | Buffer entropy<br />string password | Promise&lt;Ecc.ExtKey&gt; |

### SRP functions

```javascript
interface RegisterResult {
    s: Buffer;
    v: Buffer;
};

interface LoginStep1Result {
    A: Buffer;
    K: Buffer;
    M1: Buffer;
    M2: Buffer;
};
```

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| srpRegister | | Buffer N<br />Buffer g<br />string I<br />string P | Promise&lt;RegisterResult&gt; |
| srpLoginStep1 | | Buffer N<br />Buffer g<br />Buffer s<br />Buffer B<br />Buffer k<br />string I<br />string P | Promise&lt;LoginStep1Result&gt; |
| srpLoginStep2 | | Buffer clientM2<br />Buffer serverM2 | Promise&lt;void&gt; |

### Random generation

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| randomFeed | | Buffer feed | void |
| randomInt32 | | void | number |
| randomDouble | | void | number |
| randomBytes | | number count | Buffer |
| randomBits | | number count | Buffer |
| randomBN | | BN max | BN |

### Misc.

| Name | Description | Params | Result |
|:-----|:------------|:-------|:-------|
| reductKey | Reducts 32-bytes long key to 16-bytes long by SHA-256 and takes first 16 bytes | Buffer key | Promise&lt;Buffer&gt; |
| generateIv | Generates IV from index for AES (16 bytes long) | Buffer key<br />number index | Promise&lt;Buffer&gt; |

### Build

```
gulp
```

### Test

#### Browser tests
```
npm start
```
and browse http://localhost:8123/

#### Mocha tests
```
npm test
```

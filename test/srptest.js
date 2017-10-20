var assert   = require('assert');
var BN       = require('bn.js').BN;
var SrpLogic = require('../src/srp').SrpLogic;
var CryptoService = require('../src/crypto/Service');

// Using test vector from RFC 5054
// "Using the Secure Remote Password (SRP) Protocol for TLS Authentication"
// https://tools.ietf.org/html/rfc5054#appendix-B
// Please note that in that RFC the sha1 is used as the hash function 
// while our default is sha256.

// 1024 bit group 
var N = new BN(
    'EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C' +
    '9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4' +
    '8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29' +
    '7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A' +
    'FD5138FE 8376435B 9FC61D2F C0EB06E3'.replace(/\s/g,""), 
    "hex");
var g = new BN(2);

// Username, password and salt
var I = "alice";
var P = "password123";
var s = Buffer.from('BEB25379 D1A8581E B5A72767 3A2441EE'.replace(/\s/g,''),'hex');

var k = new BN('7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F'.replace(/\s/g,''), 'hex');
var x = new BN('94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124'.replace(/\s/g,''), 'hex');
var v = new BN(
    '7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812' +
    '9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5' +
    'C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5' +
    'EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78' +
    'E955A5E2 9E7AB245 DB2BE315 E2099AFB'.replace(/\s/g,""),
    'hex');

var a = new BN(
    '60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD' +
    'DA2D4393'.replace(/\s/g,""),
    'hex');
var b = new BN(
    'E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1' +
    '05284D20'.replace(/\s/g,""),
    'hex');

var A = new BN(
    '61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4' +
    '4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC' +
    '8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44' +
    'BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA' +
    'B349EF5D 76988A36 72FAC47B 0769447B'.replace(/\s/g,""),
    'hex');
var B = new BN(
    'BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011' +
    'BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99' +
    '6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA' +
    '37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE' +
    'EB4012B7 D7665238 A8E3FB00 4B117B58'.replace(/\s/g,""),
    'hex');

var u = new BN('CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019'.replace(/\s/g,''), 'hex');

var S = new BN(
    'B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D' +
    '233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C' +
    '41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F' +
    '3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D' +
    'C346D7E4 74B29EDE 8A469FFE CA686E5A'.replace(/\s/g,""),
    'hex');

var sha1Srp   = new SrpLogic("sha1");

describe('SrpLogic', function() {
  it('should compute proper k', function() {
    var result = sha1Srp.get_k(N, g);
    assert.equal(result.toString('hex'), k.toString('hex'));
  });
  it('should compute proper x', function() {
    var result = sha1Srp.get_x(s, I, P);
    assert.equal(result.toString('hex'), x.toString('hex'));
  });
  it('should compute proper v', function() {
    var result = sha1Srp.get_v(g, N, x);
    assert.equal(result.toString('hex'), v.toString('hex'));
  });
  it('should compute proper client A', function() {
    var result = sha1Srp.get_A(g, N, a);
    assert.equal(result.toString('hex'), A.toString('hex'));
  });
  it('should compute proper server B', function() {
    var result = sha1Srp.get_B(g, N, k, b, v);
    assert.equal(result.toString('hex'), B.toString('hex'));
  });
  it('should compute proper u', function() {
    var result = sha1Srp.get_u(A, B, N);
    assert.equal(result.toString('hex'), u.toString('hex'));
  });
  it('should compute proper client premaster secret', function() {
    var result = sha1Srp.getClient_S(B, k, v, a, u, x, N);
    assert.equal(result.toString('hex'), S.toString('hex'));
  });
  it('should compute proper server premaster secret', function() {
    var result = sha1Srp.getServer_S(A, v, u, b, N);
    assert.equal(result.toString('hex'), S.toString('hex'));
  });
  it('should provide proper verifier on register', function() {
    var result = sha1Srp.register(N, g, I, P, s);
    assert.equal(result.v.toString('hex', 2), v.toString('hex', 2));
  });
  it('should provide proper values on first step of login', function() {
    var result = sha1Srp.login_step1(N, g, s, B, I, P, a);
    assert.equal(result.A.toString('hex'), A.toString('hex', 2));
    assert.equal(result.S.toString('hex'), S.toString('hex', 2));
  });
  it('should work with random values of client a and server b and sha512', function() {
    var regInfo = sha1Srp.register(N, g, I, P);
    var server  = sha1Srp.server_init(N, g, regInfo.s, regInfo.v);
    var client  = sha1Srp.login_step1(N, g, regInfo.s, server.B, I, P);
    var server2 = sha1Srp.server_exchange(N, g, client.A, client.M1, regInfo.v, server.B, server.b);

    assert.equal(client.S.toString('hex'),  server2.S.toString('hex'));
    assert.equal(client.M2.toString('hex'), server2.M2.toString('hex'));
    assert.equal(client.K.toString('hex'),  server2.K.toString('hex'));
  });
});

describe('CryptoService', function() {
  it('#srpRegister', function() {
    var Nb = N.toArrayLike(Buffer);
    var gb = g.toArrayLike(Buffer);
    return CryptoService.srpRegister(Nb, gb, I, P)
      .then((regInfo) => { 
        var srp = new SrpLogic("sha256");
        var expected = srp.register(N, g, I, P, regInfo.s);
        assert.equal(regInfo.s.toString('hex'), expected.s.toString('hex'));
        assert.equal(regInfo.v.toString('hex'), expected.v.toString('hex', 2));
      });
  });
  it('#srpLoginStep1, #srpLoginStep2', function() {
    var Nb = N.toArrayLike(Buffer);
    var gb = g.toArrayLike(Buffer);
    var s  = Buffer.from('ca7b11053e66aec3a438f271bca47666', 'hex');
    var v =  Buffer.from('56a70757063407588bef7addc54a653e83d69bf7feb3fd23f22ed08fe529ed1140914997849c49c7f2e91ff09502717580b772fd69595166143f2959ac18dcbd081031f336b4632de06abf247ab9931c589b47f2f7c99b8c47114fcbfa02f33228b2a08d6aab1bd04c23817a4aa3eb2c181f8ab72592909c92f6a65b61e0d429', 'hex');
    // fake server init
    var srp = new SrpLogic("sha256");
    var server = srp.server_init(N, g, new BN(s), new BN(v));
    var B = server.B.toArrayLike(Buffer);
    return CryptoService.srpLoginStep1(Nb, gb, s, B, null, I, P)
      .then((client) => {
        // fake server exchange
        var server2 = srp.server_exchange(N, g, new BN(client.A), new BN(client.M1), new BN(v), server.B, server.b);
        var M2 = server2.M2.toArrayLike(Buffer);
        return CryptoService.srpLoginStep2(client.M2, M2);
      });
  });
});

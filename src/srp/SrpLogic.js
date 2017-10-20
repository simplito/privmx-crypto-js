module.exports = SrpLogic;

var _crypto = require("crypto");
var BN = require("bn.js");

function PAD(x, N) {
    return x.toArrayLike(Buffer, "be", N.byteLength());
};

/**
 * SrpLogic - only to internal use, calculate SRP parameters
 * @class
 */
function SrpLogic(hash) {
    this.hash = hash;
}

SrpLogic.prototype.H = function(x) {
    return _crypto.createHash(this.hash).update(x).digest();
};

SrpLogic.prototype.get_a = function() {
    var CryptoService = require("../crypto/Service");
    return new BN(CryptoService.randomBytes(64));
};

SrpLogic.prototype.get_b = function() {
    var CryptoService = require("../crypto/Service");
    return new BN(CryptoService.randomBytes(64));
};

SrpLogic.prototype.get_s = function() {
    var CryptoService = require("../crypto/Service");
    return CryptoService.randomBytes(16);
};

SrpLogic.prototype.get_k = function(N, g) {
    return new BN( this.H(Buffer.concat([PAD(N, N), PAD(g, N)])) );
};

SrpLogic.prototype.get_v = function(g, N, x) {
    var red = BN.red(N);
    return g.toRed(red).redPow(x).fromRed();
};

 SrpLogic.prototype.get_x = function(s, I, P) {
    return new BN( this.H(Buffer.concat([s, this.H(new Buffer(I + ":" + P, "utf8"))])) );
};

SrpLogic.prototype.get_A = function(g, N, a) {
    var red = BN.red(N);
    g = g.toRed(red);
    return g.redPow(a).fromRed();
};

SrpLogic.prototype.get_B = function(g, N, k, b, v) {
    var red = BN.red(N);
    k = k.toRed(red);
    v = v.toRed(red);
    g = g.toRed(red);
    return k.redMul(v).redAdd(g.redPow(b)).fromRed();
};

SrpLogic.prototype.get_u = function(A, B, N) {
    return new BN( this.H(Buffer.concat([PAD(A, N), PAD(B, N)])) );
};

SrpLogic.prototype.getClient_S = function(B, k, v, a, u, x, N) {
    var red = BN.red(N);
    B = B.toRed(red);
    k = k.toRed(red);
    v = v.toRed(red);
    return B.redSub(k.redMul(v)).redPow(a.add(u.mul(x))).fromRed();
};

SrpLogic.prototype.getServer_S = function(A, v, u, b, N) {
    var red = BN.red(N);
    A = A.toRed(red);
    v = v.toRed(red);
    return A.redMul(v.redPow(u)).redPow(b).fromRed();
};

SrpLogic.prototype.get_M1 = function(A, B, S, N) {
    return new BN( this.H(Buffer.concat([PAD(A, N), PAD(B, N), PAD(S, N)])) );
};

SrpLogic.prototype.get_M2 = function(A, M1, S, N) {
    return new BN( this.H(Buffer.concat([PAD(A, N), PAD(M1, N), PAD(S, N)])) );
};

SrpLogic.prototype.get_K = function(S, N) {
    return new BN( this.H(PAD(S, N)) );
};

SrpLogic.prototype.valid_A = function(A, N) {
    return A.mod(N).eqn(0) === false;
};

SrpLogic.prototype.valid_B = function(B, N) {
    return B.mod(N).eqn(0) === false;
};

//==========================================

SrpLogic.prototype.register = function(N, g, I, P, s) {
    var s = s || this.get_s();
    var x = this.get_x(s, I, P);
    var v = this.get_v(g, N, x);
    
    return {
        s: s,
        v: v
    };
};

SrpLogic.prototype.server_init = function(N, g, s, v, b) {
    var k = this.get_k(N, g);
    var b = b || this.get_b();
    var B = this.get_B(g, N, k, b, v);
    return {
      b: b,
      B: B
    };
};

SrpLogic.prototype.server_exchange = function(N, g, A, M1, v, B, b) {
    var u   = this.get_u(A, B, N);

    var S   = this.getServer_S(A, v, u, b, N);
    var M2  = this.get_M2(A, M1, S, N);
    var K   = this.get_K(S, N);

    return {
      S: S,
      u: u,
      K: K,
      M2: M2
    };
};

SrpLogic.prototype.login_step1 = function(N, g, s, B, I, P, a) {
    if (!this.valid_B(B, N)) {
        throw new Error('InvalidBException');
    }
    var k = this.get_k(N, g);
    var a = a || this.get_a();
    var A = this.get_A(g, N, a);
    var x = this.get_x(s, I, P);
    var v = this.get_v(g, N, x);
    var u = this.get_u(A, B, N);
    var S = this.getClient_S(B, k, v, a, u, x, N);
    var M1 = this.get_M1(A, B, S, N);
    
    var K = this.get_K(S, N);
    var M2 = this.get_M2(A, M1, S, N);
    
    return {
        A: A,
        u: u,
        S: S,
        K: K,
        M1: M1,
        M2: M2,
    };
};

SrpLogic.prototype.login_step2 = function(clientM2, serverM2) {
    if (!clientM2.eq(serverM2)) {
        throw new Error('DifferentM2Exception - ' + clientM2 + ', ' + serverM2);
    }
};


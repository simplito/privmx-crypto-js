var BN      = require("bn.js").BN;
var prime   = require("./prime");
var Q       = require("q");
const utils = require("../openssl/openssl-utils");
const oid   = require("../openssl/oid");

module.exports = {
  generate: generate,
  generateKey: generateKey
};

function generateKey(bits, rng)
{
  return Q().then(() => {
    var key = generate(bits, rng);

    var rsapk = {
      version: 0,
      modulus: key.n,
      publicExponent:  key.e,
      privateExponent: key.d,
      prime1: key.p,
      prime2: key.q,
      exponent1: key.dp,
      exponent2: key.dq,
      coefficient: key.qi
    };

    var algorithm = {
      algorithm: oid.idrsaEncryption.split('.'),
      parameters: Buffer.from("0500", "hex") // ASN1 NULL
    };
    var key = utils.asn.RSAPrivateKey.encode(rsapk, 'der');

    return utils.encodePrivateKey(algorithm, key, "pem");
  });
};

function generate(bits, rng) {
  var bitsp = ((bits + 1) / 2) | 0;
  var bitsq = bits - bitsp;
  
  var e = new BN(65537);
  var p;
  var pp;
  var q;
  var pq;

  for(;;) {
    p = prime.generate(bitsp, rng);
    pp = p.subn(1);
    if (pp.gcd(e).eqn(1))
      break;
  }
  for(;;) {
    q = prime.generate(bitsq, rng);
    if (p.eq(q))
      continue;
    pq = q.subn(1);
    if (pq.gcd(e).eqn(1))
      break;
  }
  if (p.cmp(q) < 0) {
    var tmp = p;
    p = q;
    q = tmp;
    tmp = pp;
    pp = pq;
    pq = tmp;
  }

  var n  = p.mul(q);
  var fi = pp.mul(pq);
  var d  = e.invm(fi);
  var dp = d.mod(pp); // == e.invm(p.subn(1));
  var dq = d.mod(pq); // == e.invm(q.subn(1));
  var qi = q.invm(p);

  return { n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi };
}

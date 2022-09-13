/* Schnorr NIZK for secp256k1 curve */
const crypto = require("crypto");
const secp256k1 = require('noble-secp256k1');
var assert = require('assert');
const fs = require('fs');
const bn128 = require('rustbn.js')

class NIZK_proof {
	constructor(t, c, s, i){
		this.t = t;
		this.c = c;
		this.s = s;
		this.i = i;
	}
}

function proof (x) {
	// Commitment keys
	const v = secp256k1.utils.randomPrivateKey();
	const V = Buffer.from(secp256k1.getPublicKey(v));

	// get the public key of the secret (Which is to be proved)
	const Q = Buffer.from(secp256k1.getPublicKey(x));

	// challenge through a Fiat-Shamir transformation.
	// FIXME: Concat userID, timestamp or some info to this!
	const challenge = crypto.createHash('sha256').update(Buffer.concat([Q,V])).digest('hex');
	const hashint = BigInt("0x"+challenge)

	// r = v - x*c % n 
	const res = BigInt("0x" + Buffer.from(v).toString('hex')) - BigInt("0x" + Buffer.from(x).toString('hex')) * hashint % secp256k1.CURVE.n;
	return new NIZK_proof(V, hashint, res, Q);
}

function verify(y){
	// Sanity checking for y
	assert (y instanceof NIZK_proof)

	// This will be needed for negative numbers
	while (y.s < BigInt("0")){
		y.s += secp256k1.CURVE.n
	}

	const ft = secp256k1.Point.BASE.multiply(y.s);
	const Qc = secp256k1.Point.fromHex(y.i).multiply(y.c);

	// lhs = V
	// rhs = G x [r] + Q x [c]
	const lhs = secp256k1.Point.fromHex(y.t);
	const rhs = ft.add(Qc)
	assert(lhs.equals(rhs))
	return true
}

const IV_LENGTH = 16;
const iv = crypto.randomBytes(IV_LENGTH);

function aesEncrypt(data, key) {
    const cipher = crypto.createCipheriv('aes256', key, iv);
    var crypted = cipher.update(data, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}

function aesDecrypt(encrypted, key) {
    const decipher = crypto.createDecipheriv('aes256', key, iv);
    var decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function loadKey(file) {
    // key实际上就是PEM编码的字符串:
    return fs.readFileSync(file, 'utf8');
}

(async () => {

// 1. Initialization

/* TA */
let t1 = secp256k1.utils.randomPrivateKey();
let T1 = secp256k1.getPublicKey(t1);

let t2 = secp256k1.utils.randomPrivateKey();
let T2 = secp256k1.getPublicKey(t2);

/* PKG */
let p1 = secp256k1.utils.randomPrivateKey();
let P1 = secp256k1.getPublicKey(p1);

let p2 = secp256k1.utils.randomPrivateKey();
let P2 = secp256k1.getPublicKey(p2);

/* RSU */
let r1 = secp256k1.utils.randomPrivateKey();
let R1 = secp256k1.getPublicKey(r1);

let r2 = secp256k1.utils.randomPrivateKey();
let R2 = secp256k1.getPublicKey(r2);

/* Vehicle */
let v1_1 = secp256k1.utils.randomPrivateKey();
let V1_1 = secp256k1.getPublicKey(v1_1);

let v1_2 = secp256k1.utils.randomPrivateKey();
let V1_2 = secp256k1.getPublicKey(v1_2);

let v2_1 = secp256k1.utils.randomPrivateKey();
let V2_1 = secp256k1.getPublicKey(v2_1);

let v2_2 = secp256k1.utils.randomPrivateKey();
let V2_2 = secp256k1.getPublicKey(v2_2);

/* C_RSU */
let hash_algo = "sha256";
const R1_HASH = await secp256k1.utils.sha256(Buffer.from(R1).toString('hex'));
const C_RSU1 = await secp256k1.sign(R1_HASH, t1);

const R2_HASH = await secp256k1.utils.sha256(Buffer.from(R2).toString('hex'));
const C_RSU2 = await secp256k1.sign(R2_HASH, t2);

// 2. Registration

/* VID */
let VID1_1 = "VID1_1";
let VID1_2 = "VID1_2";
let VID2_1 = "VID2_1";
let VID2_2 = "VID2_2";

/* Hash of VID */
const H1_1 = await secp256k1.utils.sha256(VID1_1);
const H1_2 = await secp256k1.utils.sha256(VID1_2);
const H2_1 = await secp256k1.utils.sha256(VID2_1);
const H2_2 = await secp256k1.utils.sha256(VID2_2);

/* Sign on H_i */
const alpha1_1 = await secp256k1.sign(Buffer.from(H1_1), p1);
const alpha1_2 = await secp256k1.sign(Buffer.from(H1_2), p1);
const alpha2_1 = await secp256k1.sign(Buffer.from(H2_1), p2);
const alpha2_2 = await secp256k1.sign(Buffer.from(H2_2), p2);

// console.log(alpha1_1.length, alpha1_2.length, alpha2_1.length, alpha2_2.length)

/* Tag */
let Tag1 = secp256k1.utils.randomPrivateKey();
let Tag2 = secp256k1.utils.randomPrivateKey();

/* AD_i */
let AD1 = "AD1";
let AD2 = "AD2";

// 3. intra-AD V2V (VID1_1 and VID1_2 both belong to AD1)
console.log("\n----------------------------\nintra-AD V2V\n----------------------------")

console.time("intra-AD V2V auth");

assert(verify(proof(Tag1)));

console.timeEnd("intra-AD V2V auth");

console.time("intra-AD V2V key negotiation")

let theta = secp256k1.utils.randomPrivateKey();
let Theta = secp256k1.getPublicKey(theta);
let Kab = secp256k1.Point.fromHex(V1_2).multiply(BigInt("0x" + Buffer.from(Tag1).toString('hex'))).multiply(BigInt("0x" + Buffer.from(theta).toString('hex')));

/* VIDa sends to VIDb */
let data = 'Hello, this is a secret message!';
console.time("SE")
let encryptedData = aesEncrypt(data, Kab.toHex().substring(0,32));
console.timeEnd("SE")
/* recover Kab */
let _Kab = secp256k1.Point.fromHex(Theta).multiply(BigInt("0x" + Buffer.from(Tag1).toString('hex'))).multiply(BigInt("0x" + Buffer.from(v1_2).toString('hex')));

assert(Kab.equals(_Kab));

console.time("SD")
let _data = aesDecrypt(encryptedData, _Kab.toHex().substring(0,32));
console.timeEnd("SD")
// console.log(_data);
assert(data == _data);

console.timeEnd("intra-AD V2V key negotiation")

// 4. inter-AD V2V (VID1_1 and VID2_1)
console.log("\n----------------------------\ninter-AD V2V\n----------------------------")

console.time("inter-AD V2V auth");
/* VID2_1 prove to VID1_1 */
console.time("CV")
const isSigned_2 = secp256k1.verify(alpha2_1, H2_1, P2);
console.timeEnd("CV")
assert(isSigned_2)
assert(verify(proof(v2_1)));
/* VID1_1 prove to VID2_1 */
const isSigned_1 = secp256k1.verify(alpha1_1, H1_1, P1);
assert(isSigned_1)
assert(verify(proof(v1_1)));
console.timeEnd("inter-AD V2V auth");

console.time("inter-AD V2V key negotiation")
let sigma = secp256k1.utils.randomPrivateKey();
let Sigma = secp256k1.getPublicKey(sigma);
let Kab_1 = secp256k1.Point.fromHex(P1).multiply(BigInt("0x" + Buffer.from(H2_1).toString('hex'))).multiply(BigInt("0x" + Buffer.from(sigma).toString('hex')));
let data_1 = "This is a secret msg for inter-AD V2V";
let encryptedData_1 = aesEncrypt(data_1, Kab_1.toHex().substring(0,32));
/* recover Kab_1 */
let _Kab_1 = secp256k1.Point.fromHex(Sigma).multiply(BigInt("0x" + Buffer.from(H2_1).toString('hex'))).multiply(BigInt("0x" + Buffer.from(p1).toString('hex')));

assert(Kab_1.equals(_Kab_1));
let _data_1 = aesDecrypt(encryptedData_1, _Kab_1.toHex().substring(0,32));
assert(data_1 == _data_1);

console.timeEnd("inter-AD V2V key negotiation")

// 5. intra-GD V2I (RSU1 and VID1_1)
console.log("\n----------------------------\nintra-GD V2I\n----------------------------")
console.time("intra-GD V2I auth");
let o = secp256k1.utils.randomPrivateKey();
let O = secp256k1.getPublicKey(o);

const isValid = secp256k1.verify(C_RSU1, R1_HASH, T1);
assert(isValid)
console.timeEnd("intra-GD V2I auth");

console.time("intra-GD V2I key negotiation");
let Kra = secp256k1.Point.fromHex(O).multiply(BigInt("0x" + Buffer.from(H1_1).toString('hex'))).multiply(BigInt("0x" + Buffer.from(p1).toString('hex')));
let data_ra = "This is a secret msg for intra-GD V2I";
let encryptedData_ra = aesEncrypt(data_ra, Kra.toHex().substring(0,32));
/* recover Kra */
let _Kra = secp256k1.Point.fromHex(P1).multiply(BigInt("0x" + Buffer.from(H1_1).toString('hex'))).multiply(BigInt("0x" + Buffer.from(o).toString('hex')));
assert(Kra.equals(_Kra))

let _data_ra = aesDecrypt(encryptedData_ra, _Kra.toHex().substring(0,32));
assert(data_ra == _data_ra);

console.timeEnd("intra-GD V2I key negotiation");

// 6. inter-GD V2I (RSU2 and VID1_1)
console.log("\n----------------------------\ninter-GD V2I\n----------------------------")
console.time("inter-GD V2I auth");
let x = secp256k1.utils.randomPrivateKey();
let X = secp256k1.getPublicKey(x);

const isValid_1 = secp256k1.verify(C_RSU2, R2_HASH, T2);
assert(isValid_1)
console.timeEnd("inter-GD V2I auth");

console.time("inter-GD V2I key negotiation");
let Krb = secp256k1.Point.fromHex(X).multiply(BigInt("0x" + Buffer.from(H1_1).toString('hex'))).multiply(BigInt("0x" + Buffer.from(p1).toString('hex')));
let data_rb = "This is a secret msg for inter-GD V2I";
let encryptedData_rb = aesEncrypt(data_rb, Krb.toHex().substring(0,32));
/* recover Kra */
let _Krb = secp256k1.Point.fromHex(P1).multiply(BigInt("0x" + Buffer.from(H1_1).toString('hex'))).multiply(BigInt("0x" + Buffer.from(x).toString('hex')));
assert(Krb.equals(_Krb))

let _data_rb = aesDecrypt(encryptedData_rb, _Krb.toHex().substring(0,32));
assert(data_rb == _data_rb);
console.timeEnd("inter-GD V2I key negotiation");

// 7. operation cost
console.log("\n----------------------------\nsecp256k1 point operations\n----------------------------")

let point_y = proof(v1_1);
while (point_y.s < BigInt("0")){
	point_y.s += secp256k1.CURVE.n
}
console.time("secp256k1 point multiply (PM)")
let ft = secp256k1.Point.BASE.multiply(point_y.s);
console.timeEnd("secp256k1 point multiply (PM)")

let Qc = secp256k1.Point.fromHex(point_y.i).multiply(point_y.c);
console.time("secp256k1 point add (PA)")
const rhs = ft.add(Qc)
console.timeEnd("secp256k1 point add (PA)")

// const DSb = BigInt("0x" + Buffer.from(H1_1).toString('hex')) * BigInt("0x" + Buffer.from(alpha1_1).toString('hex')) + BigInt("0x" + Buffer.from(v1_1).toString('hex'));
// console.log("DSb length: ", DSb.toString().length)

// asymmetric key
// openssl genrsa -aes256 -out rsa-key.pem 2048
// openssl rsa -in rsa-key.pem -outform PEM -out rsa-prv.pem
// openssl rsa -in rsa-key.pem -outform PEM -pubout -out rsa-pub.pem
let
    prvKey = loadKey('./rsa-prv.pem'),
    pubKey = loadKey('./rsa-pub.pem'),
    message = 'this is a secret message';

// 使用私钥加密:
console.time("AE")
let enc_by_prv = crypto.privateEncrypt(prvKey, Buffer.from(message, 'utf8'));
console.timeEnd("AE")
console.log('encrypted by private key: ' + enc_by_prv.toString('hex'));

console.time("AD")
let dec_by_pub = crypto.publicDecrypt(pubKey, enc_by_prv);
console.timeEnd("AD")
console.log('decrypted by public key: ' + dec_by_pub.toString('utf8'));

console.time("EX")
let ex_string = BigInt("0x" + Buffer.from(H1_1).toString('hex')) ** BigInt("0x" + Buffer.from(H1_1).toString('hex').substring(0,2));
// console.log("0x" + Buffer.from(H1_1).toString('hex').substring(0,2))
console.timeEnd("EX")

console.time("BPPM")
let input = '000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000042'
let output = '12e017e752e718f7d1750138f3fd97d930073164499793d9b5405a9ff30e765a11d73265f2f8035c1eb99695a20bc0e550afbc7d506f9f1a1ffcb9f0ade01454'
let _output = bn128.mul(Buffer.from(input, 'hex')).toString('hex')
console.timeEnd("BPPM")
assert(output == _output)

console.time("BPPA")
input = '0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002'
output = '030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4'
_output = bn128.add(Buffer.from(input, 'hex')).toString('hex')
console.timeEnd("BPPA")
assert(output == _output)

console.time("BP")
input = '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa'
output = '0000000000000000000000000000000000000000000000000000000000000001'
_output = bn128.pairing(Buffer.from(input, 'hex')).toString('hex')
console.timeEnd("BP")
assert(output == _output)

// AE: 1.387ms
// AD: 0.126ms
// EX: 0.883ms
// BPPM: 121.022ms
// BPPA: 3.923ms
// BP: 743.708ms
})();
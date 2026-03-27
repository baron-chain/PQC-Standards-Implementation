/**
 * Hybrid KEM: combining classical ECDH key exchange with ML-KEM.
 *
 * Hybrid KEMs ensure security holds if either the classical or
 * post-quantum component remains secure.
 *
 * Supported schemes:
 * - X25519 + ML-KEM-768 (IETF standard hybrid for TLS)
 * - ECDH-P256 + ML-KEM-768
 * - X25519 + ML-KEM-1024
 * - ECDH-P384 + ML-KEM-1024
 *
 * KDF: SHA3-256(ss_classical || ss_pq || label)
 */

import { createHash, createECDH, diffieHellman, generateKeyPairSync, createPublicKey, createPrivateKey } from 'node:crypto';
import crypto from 'node:crypto';
import { keyGen as mlkemKeyGen, encaps as mlkemEncaps, decaps as mlkemDecaps } from '../kem.js';
import { ML_KEM_768, ML_KEM_1024 } from '../params.js';

/**
 * Concatenate multiple Uint8Arrays.
 */
function concatBytes(...arrays) {
  const totalLen = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/**
 * SHA3-256 hash of the concatenation of inputs.
 */
function sha3_256(...inputs) {
  const h = createHash('sha3-256');
  for (const input of inputs) {
    h.update(input);
  }
  return new Uint8Array(h.digest());
}

/**
 * Combine shared secrets using SHA3-256(ss_classical || ss_pq || label).
 */
function combineSecrets(ssClassical, ssPQ, label) {
  return sha3_256(ssClassical, ssPQ, label);
}

// ─── X25519 helpers ──────────────────────────────────────────────────────────

function x25519KeyGen() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const pkRaw = publicKey.export({ type: 'spki', format: 'der' });
  const skRaw = privateKey.export({ type: 'pkcs8', format: 'der' });
  // Extract raw 32-byte keys from DER encoding
  // X25519 SPKI: last 32 bytes; PKCS8: last 32 bytes
  const pk = new Uint8Array(pkRaw.slice(-32));
  const sk = new Uint8Array(skRaw.slice(-32));
  return { pk, sk, publicKeyObj: publicKey, privateKeyObj: privateKey };
}

function x25519FromRawKeys(pkBytes, skBytes) {
  // Build DER-encoded SPKI for X25519 public key
  const spkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');
  const spki = Buffer.concat([spkiPrefix, Buffer.from(pkBytes)]);
  const publicKeyObj = createPublicKey({ key: spki, format: 'der', type: 'spki' });

  // Build DER-encoded PKCS8 for X25519 private key
  const pkcs8Prefix = Buffer.from('302e020100300506032b656e042204200', 'hex');
  // Actually build correct PKCS8 DER
  const pkcs8 = buildX25519PKCS8(skBytes);
  const privateKeyObj = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });

  return { publicKeyObj, privateKeyObj };
}

function buildX25519PKCS8(rawKey) {
  // X25519 PKCS8 DER structure:
  // SEQUENCE {
  //   INTEGER 0
  //   SEQUENCE { OID 1.3.101.110 }
  //   OCTET STRING { OCTET STRING { raw key } }
  // }
  const oid = Buffer.from('300506032b656e', 'hex');
  const keyOctet = Buffer.concat([Buffer.from([0x04, 0x20]), Buffer.from(rawKey)]);
  const keyWrapper = Buffer.concat([Buffer.from([0x04, keyOctet.length]), keyOctet]);
  const version = Buffer.from([0x02, 0x01, 0x00]);
  const seqContent = Buffer.concat([version, oid, keyWrapper]);
  return Buffer.concat([Buffer.from([0x30, seqContent.length]), seqContent]);
}

function buildX25519SPKI(rawKey) {
  const prefix = Buffer.from('302a300506032b656e032100', 'hex');
  return Buffer.concat([prefix, Buffer.from(rawKey)]);
}

function x25519Encaps(peerPkBytes) {
  const { pk: ephPk, sk: ephSk } = x25519KeyGen();
  const ephKeyObjs = x25519FromRawKeys(ephPk, ephSk);
  const peerSpki = buildX25519SPKI(peerPkBytes);
  const peerPubObj = createPublicKey({ key: peerSpki, format: 'der', type: 'spki' });

  const shared = crypto.diffieHellman({
    privateKey: ephKeyObjs.privateKeyObj,
    publicKey: peerPubObj,
  });
  return { ss: new Uint8Array(shared), ct: ephPk };
}

function x25519Decaps(skBytes, ctBytes) {
  const dummyPk = new Uint8Array(32); // not used for DH, but needed for key object
  // We need the actual public key that corresponds to skBytes for building the key object,
  // but for ECDH we only need the private key and peer's public key
  const pkcs8 = buildX25519PKCS8(skBytes);
  const privateKeyObj = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });

  const peerSpki = buildX25519SPKI(ctBytes);
  const peerPubObj = createPublicKey({ key: peerSpki, format: 'der', type: 'spki' });

  const shared = crypto.diffieHellman({
    privateKey: privateKeyObj,
    publicKey: peerPubObj,
  });
  return new Uint8Array(shared);
}

// ─── NIST curve ECDH helpers ─────────────────────────────────────────────────

function ecdhKeyGen(curveName) {
  const ecdh = createECDH(curveName);
  ecdh.generateKeys();
  return {
    pk: new Uint8Array(ecdh.getPublicKey()),
    sk: new Uint8Array(ecdh.getPrivateKey()),
    ecdhObj: ecdh,
  };
}

function ecdhEncaps(curveName, peerPkBytes) {
  const eph = createECDH(curveName);
  eph.generateKeys();
  const shared = eph.computeSecret(Buffer.from(peerPkBytes));
  return {
    ss: new Uint8Array(shared),
    ct: new Uint8Array(eph.getPublicKey()),
  };
}

function ecdhDecaps(curveName, skBytes, ctBytes) {
  const ecdh = createECDH(curveName);
  ecdh.setPrivateKey(Buffer.from(skBytes));
  const shared = ecdh.computeSecret(Buffer.from(ctBytes));
  return new Uint8Array(shared);
}

// ─── Scheme definitions ──────────────────────────────────────────────────────

export const HYBRID_X25519_MLKEM768 = {
  name: 'X25519-MLKEM768',
  label: new TextEncoder().encode('X25519-MLKEM768'),
  classicalType: 'x25519',
  classicalPkSize: 32,
  classicalSkSize: 32,
  classicalCtSize: 32,
  mlkemParams: ML_KEM_768,
};

export const HYBRID_ECDHP256_MLKEM768 = {
  name: 'ECDHP256-MLKEM768',
  label: new TextEncoder().encode('ECDHP256-MLKEM768'),
  classicalType: 'prime256v1',
  classicalPkSize: 65, // uncompressed point
  classicalSkSize: 32,
  classicalCtSize: 65,
  mlkemParams: ML_KEM_768,
};

export const HYBRID_X25519_MLKEM1024 = {
  name: 'X25519-MLKEM1024',
  label: new TextEncoder().encode('X25519-MLKEM1024'),
  classicalType: 'x25519',
  classicalPkSize: 32,
  classicalSkSize: 32,
  classicalCtSize: 32,
  mlkemParams: ML_KEM_1024,
};

export const HYBRID_ECDHP384_MLKEM1024 = {
  name: 'ECDHP384-MLKEM1024',
  label: new TextEncoder().encode('ECDHP384-MLKEM1024'),
  classicalType: 'secp384r1',
  classicalPkSize: 97, // uncompressed point
  classicalSkSize: 48,
  classicalCtSize: 97,
  mlkemParams: ML_KEM_1024,
};

// ─── Hybrid KEM API ──────────────────────────────────────────────────────────

/**
 * Generate a hybrid key pair.
 * @param {object} scheme - Hybrid scheme definition
 * @returns {{ ek: Uint8Array, dk: Uint8Array, classicalEkSize: number, classicalDkSize: number }}
 */
export function hybridKeyGen(scheme) {
  let classicalPk, classicalSk;

  if (scheme.classicalType === 'x25519') {
    const kp = x25519KeyGen();
    classicalPk = kp.pk;
    classicalSk = kp.sk;
  } else {
    const kp = ecdhKeyGen(scheme.classicalType);
    classicalPk = kp.pk;
    classicalSk = kp.sk;
  }

  const { ek: pqEk, dk: pqDk } = mlkemKeyGen(scheme.mlkemParams);

  return {
    ek: concatBytes(classicalPk, pqEk),
    dk: concatBytes(classicalSk, pqDk),
    classicalEkSize: classicalPk.length,
    classicalDkSize: classicalSk.length,
  };
}

/**
 * Encapsulate using a hybrid scheme.
 * @param {object} scheme - Hybrid scheme definition
 * @param {Uint8Array} ek - Combined encapsulation key
 * @param {number} classicalEkSize - Size of classical portion
 * @returns {{ sharedSecret: Uint8Array, ciphertext: Uint8Array, classicalCtSize: number }}
 */
export function hybridEncaps(scheme, ek, classicalEkSize) {
  const classicalPk = ek.slice(0, classicalEkSize);
  const pqEk = ek.slice(classicalEkSize);

  let ssClassical, ctClassical;

  if (scheme.classicalType === 'x25519') {
    const result = x25519Encaps(classicalPk);
    ssClassical = result.ss;
    ctClassical = result.ct;
  } else {
    const result = ecdhEncaps(scheme.classicalType, classicalPk);
    ssClassical = result.ss;
    ctClassical = result.ct;
  }

  const { K: ssPQ, c: ctPQ } = mlkemEncaps(pqEk, scheme.mlkemParams);

  const combinedSS = combineSecrets(ssClassical, ssPQ, scheme.label);

  return {
    sharedSecret: combinedSS,
    ciphertext: concatBytes(ctClassical, ctPQ),
    classicalCtSize: ctClassical.length,
  };
}

/**
 * Decapsulate using a hybrid scheme.
 * @param {object} scheme - Hybrid scheme definition
 * @param {Uint8Array} dk - Combined decapsulation key
 * @param {Uint8Array} ct - Combined ciphertext
 * @param {number} classicalDkSize - Size of classical secret key portion
 * @param {number} classicalCtSize - Size of classical ciphertext portion
 * @returns {Uint8Array} Combined 32-byte shared secret
 */
export function hybridDecaps(scheme, dk, ct, classicalDkSize, classicalCtSize) {
  const classicalSk = dk.slice(0, classicalDkSize);
  const pqDk = dk.slice(classicalDkSize);

  const ctClassical = ct.slice(0, classicalCtSize);
  const ctPQ = ct.slice(classicalCtSize);

  let ssClassical;

  if (scheme.classicalType === 'x25519') {
    ssClassical = x25519Decaps(classicalSk, ctClassical);
  } else {
    ssClassical = ecdhDecaps(scheme.classicalType, classicalSk, ctClassical);
  }

  const ssPQ = mlkemDecaps(pqDk, ctPQ, scheme.mlkemParams);

  return combineSecrets(ssClassical, ssPQ, scheme.label);
}

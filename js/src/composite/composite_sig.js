/**
 * Composite Signature Schemes — ML-DSA + Ed25519 / ECDSA-P256
 *
 * Signature format: len(sig_classical) [4 bytes LE] || sig_classical || sig_pq
 */

import crypto from 'node:crypto';
import { keyGen as mldsaKeyGen, sign as mldsaSign, verify as mldsaVerify } from '../mldsa/dsa.js';
import { ML_DSA_44, ML_DSA_65, ML_DSA_87 } from '../mldsa/params.js';

// ---------------------------------------------------------------------------
// Scheme definitions
// ---------------------------------------------------------------------------

export const MLDSA65_ED25519 = {
  name: 'ML-DSA-65+Ed25519',
  pqParams: ML_DSA_65,
  classical: 'ed25519',
};

export const MLDSA65_ECDSA_P256 = {
  name: 'ML-DSA-65+ECDSA-P256',
  pqParams: ML_DSA_65,
  classical: 'ecdsa-p256',
};

export const MLDSA87_ED25519 = {
  name: 'ML-DSA-87+Ed25519',
  pqParams: ML_DSA_87,
  classical: 'ed25519',
};

export const MLDSA44_ED25519 = {
  name: 'ML-DSA-44+Ed25519',
  pqParams: ML_DSA_44,
  classical: 'ed25519',
};

// ---------------------------------------------------------------------------
// Classical key helpers
// ---------------------------------------------------------------------------

function classicalPKSize(scheme) {
  return scheme.classical === 'ed25519' ? 32 : 65; // uncompressed P-256
}

function classicalSKSize(scheme) {
  return scheme.classical === 'ed25519' ? 32 : 32; // seed / scalar
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

function genClassicalEd25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  // Export raw key material
  const pkRaw = publicKey.export({ type: 'spki', format: 'der' });
  // Ed25519 SPKI DER: 12-byte prefix then 32-byte key
  const pk = new Uint8Array(pkRaw.subarray(pkRaw.length - 32));
  const skRaw = privateKey.export({ type: 'pkcs8', format: 'der' });
  // Ed25519 PKCS8 DER: prefix then 34 bytes (02 20 + 32-byte seed)
  const sk = new Uint8Array(skRaw.subarray(skRaw.length - 32));
  return { pk, sk, privateKey, publicKey };
}

function genClassicalEcdsaP256() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const pkRaw = publicKey.export({ type: 'spki', format: 'der' });
  const skRaw = privateKey.export({ type: 'pkcs8', format: 'der' });
  // Extract the uncompressed public key (65 bytes: 04 || x || y)
  // In SEC1/SPKI DER, the last 65+ bytes are the key
  const pkUncompressed = extractEcPublicKey(pkRaw);
  const skScalar = extractEcPrivateKey(skRaw);
  return { pk: pkUncompressed, sk: skScalar, privateKey, publicKey };
}

function extractEcPublicKey(spkiDer) {
  // Find the 0x04 uncompressed point marker followed by 64 bytes
  for (let i = spkiDer.length - 65; i >= 0; i--) {
    if (spkiDer[i] === 0x04) {
      return new Uint8Array(spkiDer.subarray(i, i + 65));
    }
  }
  throw new Error('Could not extract EC public key from SPKI DER');
}

function extractEcPrivateKey(pkcs8Der) {
  // The private key scalar is 32 bytes, usually preceded by 04 20 in the OCTET STRING
  for (let i = 0; i < pkcs8Der.length - 33; i++) {
    if (pkcs8Der[i] === 0x04 && pkcs8Der[i + 1] === 0x20) {
      return new Uint8Array(pkcs8Der.subarray(i + 2, i + 2 + 32));
    }
  }
  throw new Error('Could not extract EC private key from PKCS8 DER');
}

/**
 * Generate a composite key pair.
 * Returns { pk, sk, scheme, _classicalPrivateKey, _classicalPublicKey }
 * The _classical* fields hold node:crypto KeyObject for signing.
 */
export function keyGen(scheme) {
  let classicalResult;
  if (scheme.classical === 'ed25519') {
    classicalResult = genClassicalEd25519();
  } else {
    classicalResult = genClassicalEcdsaP256();
  }

  const { pk: pqPK, sk: pqSK } = mldsaKeyGen(scheme.pqParams);

  const pk = new Uint8Array(classicalResult.pk.length + pqPK.length);
  pk.set(classicalResult.pk, 0);
  pk.set(pqPK, classicalResult.pk.length);

  const sk = new Uint8Array(classicalResult.sk.length + pqSK.length);
  sk.set(classicalResult.sk, 0);
  sk.set(pqSK, classicalResult.sk.length);

  return {
    pk,
    sk,
    scheme,
    _classicalPrivateKey: classicalResult.privateKey,
    _classicalPublicKey: classicalResult.publicKey,
  };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

function signClassical(kp, msg) {
  if (kp.scheme.classical === 'ed25519') {
    return crypto.sign(null, Buffer.from(msg), kp._classicalPrivateKey);
  } else {
    // ECDSA-P256 with SHA-256
    return crypto.sign('sha256', Buffer.from(msg), kp._classicalPrivateKey);
  }
}

/**
 * Sign a message with composite scheme.
 * Returns Uint8Array: len(sig_classical)[4 LE] || sig_classical || sig_pq
 */
export function sign(kp, msg) {
  const sigClassical = new Uint8Array(signClassical(kp, msg));
  const skPQ = kp.sk.subarray(classicalSKSize(kp.scheme));
  const sigPQ = mldsaSign(skPQ, new Uint8Array(msg), kp.scheme.pqParams);

  const out = new Uint8Array(4 + sigClassical.length + sigPQ.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, sigClassical.length, true); // little-endian
  out.set(sigClassical, 4);
  out.set(sigPQ, 4 + sigClassical.length);
  return out;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

function rebuildClassicalPublicKey(scheme, pkRaw) {
  if (scheme.classical === 'ed25519') {
    // Build SPKI DER for Ed25519
    const prefix = Buffer.from('302a300506032b6570032100', 'hex');
    const spki = Buffer.concat([prefix, Buffer.from(pkRaw)]);
    return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } else {
    // Build SPKI DER for P-256 uncompressed
    const prefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
    const spki = Buffer.concat([prefix, Buffer.from(pkRaw)]);
    return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  }
}

/**
 * Verify a composite signature. Returns true only if BOTH components verify.
 */
export function verify(scheme, pk, msg, sig) {
  if (sig.length < 4) return false;
  const view = new DataView(sig.buffer, sig.byteOffset, sig.byteLength);
  const classicalSigLen = view.getUint32(0, true);
  if (sig.length < 4 + classicalSigLen) return false;

  const sigClassical = sig.subarray(4, 4 + classicalSigLen);
  const sigPQ = sig.subarray(4 + classicalSigLen);

  const pkClassical = pk.subarray(0, classicalPKSize(scheme));
  const pkPQ = pk.subarray(classicalPKSize(scheme));

  // Verify classical
  let classicalOK;
  try {
    const pubKeyObj = rebuildClassicalPublicKey(scheme, pkClassical);
    if (scheme.classical === 'ed25519') {
      classicalOK = crypto.verify(null, Buffer.from(msg), pubKeyObj, Buffer.from(sigClassical));
    } else {
      classicalOK = crypto.verify('sha256', Buffer.from(msg), pubKeyObj, Buffer.from(sigClassical));
    }
  } catch {
    classicalOK = false;
  }

  // Verify PQ
  const pqOK = mldsaVerify(pkPQ, new Uint8Array(msg), sigPQ, scheme.pqParams);

  return classicalOK && pqOK;
}

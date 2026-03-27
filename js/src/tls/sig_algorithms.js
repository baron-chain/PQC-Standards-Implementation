/**
 * PQC Signature Algorithms for TLS 1.3.
 *
 * Defines PQC and composite signature algorithms for the `signature_algorithms`
 * extension (CertificateVerify), along with sign/verify helpers.
 */

import { keyGen as mldsaKeyGen, sign as mldsaSign, verify as mldsaVerify } from '../mldsa/dsa.js';
import { ML_DSA_44, ML_DSA_65, ML_DSA_87 } from '../mldsa/params.js';
import {
  MLDSA65_ED25519, MLDSA87_ED25519,
  keyGen as compositeKeyGen, sign as compositeSign, verify as compositeVerify,
} from '../composite/composite_sig.js';

/** TLS 1.3 signature algorithm code points for PQC. */
export const SignatureAlgorithm = Object.freeze({
  MLDSA44:         0x0904,
  MLDSA65:         0x0905,
  MLDSA87:         0x0906,
  MLDSA65_ED25519: 0x0907,
  MLDSA87_ED25519: 0x0908,
});

/** All defined signature algorithms. */
export const ALL_SIGNATURE_ALGORITHMS = Object.freeze([
  SignatureAlgorithm.MLDSA44,
  SignatureAlgorithm.MLDSA65,
  SignatureAlgorithm.MLDSA87,
  SignatureAlgorithm.MLDSA65_ED25519,
  SignatureAlgorithm.MLDSA87_ED25519,
]);

/** Human-readable name for a signature algorithm. */
export function signatureAlgorithmName(algId) {
  switch (algId) {
    case SignatureAlgorithm.MLDSA44: return 'MLDSA44';
    case SignatureAlgorithm.MLDSA65: return 'MLDSA65';
    case SignatureAlgorithm.MLDSA87: return 'MLDSA87';
    case SignatureAlgorithm.MLDSA65_ED25519: return 'MLDSA65_ED25519';
    case SignatureAlgorithm.MLDSA87_ED25519: return 'MLDSA87_ED25519';
    default: return 'Unknown';
  }
}

/** Look up a signature algorithm by code point. */
export function signatureAlgorithmFromCodePoint(cp) {
  if (ALL_SIGNATURE_ALGORITHMS.includes(cp)) return cp;
  return undefined;
}

/** Whether the algorithm is a composite (hybrid) signature. */
export function isComposite(algId) {
  return algId === SignatureAlgorithm.MLDSA65_ED25519 ||
         algId === SignatureAlgorithm.MLDSA87_ED25519;
}

function mldsaParams(algId) {
  switch (algId) {
    case SignatureAlgorithm.MLDSA44: return ML_DSA_44;
    case SignatureAlgorithm.MLDSA65: return ML_DSA_65;
    case SignatureAlgorithm.MLDSA87: return ML_DSA_87;
    default: throw new Error('Not a pure ML-DSA algorithm');
  }
}

function compositeScheme(algId) {
  switch (algId) {
    case SignatureAlgorithm.MLDSA65_ED25519: return MLDSA65_ED25519;
    case SignatureAlgorithm.MLDSA87_ED25519: return MLDSA87_ED25519;
    default: throw new Error('Not a composite algorithm');
  }
}

/**
 * Generate a signing key pair.
 *
 * For composite algorithms, the returned object includes a `_compositeKP`
 * property containing the full composite key pair (including JCA key objects
 * needed for signing).
 *
 * @param {number} algId - Signature algorithm code point
 * @returns {{ pk: Uint8Array, sk: Uint8Array, algorithm: number, _compositeKP?: object }}
 */
export function generateSigningKey(algId) {
  if (isComposite(algId)) {
    const scheme = compositeScheme(algId);
    const kp = compositeKeyGen(scheme);
    return { pk: kp.pk, sk: kp.sk, algorithm: algId, _compositeKP: kp };
  }
  const params = mldsaParams(algId);
  const { pk, sk } = mldsaKeyGen(params);
  return { pk, sk, algorithm: algId };
}

/**
 * Sign a TLS 1.3 CertificateVerify handshake hash.
 *
 * For composite algorithms, pass the full key pair object from `generateSigningKey`
 * as the `skOrKeyPair` parameter.
 *
 * @param {number} algId
 * @param {Uint8Array|object} skOrKeyPair - Secret key bytes (pure) or full key pair object (composite)
 * @param {Uint8Array} handshakeHash - Transcript hash
 * @returns {Uint8Array} Signature bytes
 */
export function signHandshake(algId, skOrKeyPair, handshakeHash) {
  if (isComposite(algId)) {
    // For composite, skOrKeyPair should be the full key pair with _compositeKP
    const kp = skOrKeyPair._compositeKP || skOrKeyPair;
    return compositeSign(kp, handshakeHash);
  }
  const params = mldsaParams(algId);
  return mldsaSign(skOrKeyPair, handshakeHash, params);
}

/**
 * Verify a TLS 1.3 CertificateVerify signature.
 * @param {number} algId
 * @param {Uint8Array} pk - Public key
 * @param {Uint8Array} handshakeHash
 * @param {Uint8Array} signature
 * @returns {boolean}
 */
export function verifyHandshake(algId, pk, handshakeHash, signature) {
  if (isComposite(algId)) {
    const scheme = compositeScheme(algId);
    return compositeVerify(scheme, pk, handshakeHash, signature);
  }
  const params = mldsaParams(algId);
  return mldsaVerify(pk, handshakeHash, signature, params);
}

/**
 * TLS 1.3 PQC Cipher Suite definitions.
 */

import { NamedGroup } from './named_groups.js';
import { SignatureAlgorithm } from './sig_algorithms.js';

/** AEAD algorithms used in TLS 1.3. */
export const AeadAlgorithm = Object.freeze({
  AES_128_GCM_SHA256: 'TLS_AES_128_GCM_SHA256',
  AES_256_GCM_SHA384: 'TLS_AES_256_GCM_SHA384',
  CHACHA20_POLY1305_SHA256: 'TLS_CHACHA20_POLY1305_SHA256',
});

/** AEAD key lengths in bytes. */
export function aeadKeyLength(aead) {
  switch (aead) {
    case AeadAlgorithm.AES_128_GCM_SHA256: return 16;
    case AeadAlgorithm.AES_256_GCM_SHA384: return 32;
    case AeadAlgorithm.CHACHA20_POLY1305_SHA256: return 32;
    default: return 0;
  }
}

/** AEAD hash lengths for HKDF. */
export function aeadHashLength(aead) {
  switch (aead) {
    case AeadAlgorithm.AES_128_GCM_SHA256: return 32;
    case AeadAlgorithm.AES_256_GCM_SHA384: return 48;
    case AeadAlgorithm.CHACHA20_POLY1305_SHA256: return 32;
    default: return 0;
  }
}

/** TLS_AES_128_GCM_SHA256 with ML-KEM-768 and ML-DSA-65. */
export const TLS_AES_128_GCM_SHA256_MLKEM768 = Object.freeze({
  id: 0x13010768,
  name: 'TLS_AES_128_GCM_SHA256_MLKEM768',
  aead: AeadAlgorithm.AES_128_GCM_SHA256,
  keyExchange: NamedGroup.MLKEM768,
  signature: SignatureAlgorithm.MLDSA65,
});

/** TLS_AES_256_GCM_SHA384 with X25519+ML-KEM-768 hybrid and ML-DSA-65+Ed25519 composite. */
export const TLS_AES_256_GCM_SHA384_X25519MLKEM768 = Object.freeze({
  id: 0x13026399,
  name: 'TLS_AES_256_GCM_SHA384_X25519MLKEM768',
  aead: AeadAlgorithm.AES_256_GCM_SHA384,
  keyExchange: NamedGroup.X25519MLKEM768,
  signature: SignatureAlgorithm.MLDSA65_ED25519,
});

/** All defined PQC cipher suites. */
export const ALL_CIPHER_SUITES = Object.freeze([
  TLS_AES_128_GCM_SHA256_MLKEM768,
  TLS_AES_256_GCM_SHA384_X25519MLKEM768,
]);

/**
 * Look up a cipher suite by ID.
 * @param {number} id
 * @returns {object|undefined}
 */
export function cipherSuiteById(id) {
  return ALL_CIPHER_SUITES.find(cs => cs.id === id);
}

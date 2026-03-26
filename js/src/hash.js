/**
 * Hash functions for ML-KEM (FIPS 203)
 * Uses Node.js built-in crypto module for SHA3 and SHAKE.
 */

import { createHash, createHmac } from 'node:crypto';

/**
 * G(input) - SHA3-512
 * Returns { rho: Uint8Array(32), sigma: Uint8Array(32) }
 * @param {Uint8Array} input
 * @returns {{ rho: Uint8Array, sigma: Uint8Array }}
 */
export function G(input) {
  const hash = createHash('sha3-512');
  hash.update(input);
  const digest = hash.digest();
  return {
    rho: new Uint8Array(digest.buffer, digest.byteOffset, 32),
    sigma: new Uint8Array(digest.buffer, digest.byteOffset + 32, 32),
  };
}

/**
 * H(input) - SHA3-256, returns 32-byte digest.
 * @param {Uint8Array} input
 * @returns {Uint8Array}
 */
export function H(input) {
  const hash = createHash('sha3-256');
  hash.update(input);
  const digest = hash.digest();
  return new Uint8Array(digest.buffer, digest.byteOffset, digest.length);
}

/**
 * J(input) - SHAKE-256 with 32-byte output.
 * @param {Uint8Array} input
 * @returns {Uint8Array}
 */
export function J(input) {
  const hash = createHash('shake256', { outputLength: 32 });
  hash.update(input);
  const digest = hash.digest();
  return new Uint8Array(digest.buffer, digest.byteOffset, digest.length);
}

/**
 * XOF(rho, i, j) - SHAKE-128 extendable output.
 * Pre-generates 672 bytes (enough for SampleNTT rejection sampling).
 * Returns a reader object with a bytes() method.
 * @param {Uint8Array} rho - 32-byte seed
 * @param {number} i - row index
 * @param {number} j - column index
 * @returns {{ bytes: () => Uint8Array }}
 */
export function XOF(rho, i, j) {
  const input = new Uint8Array(rho.length + 2);
  input.set(rho);
  input[rho.length] = j;      // FIPS 203: XOF takes rho || j || i (byte order per spec)
  input[rho.length + 1] = i;
  const hash = createHash('shake128', { outputLength: 672 });
  hash.update(input);
  const output = hash.digest();
  return {
    bytes() {
      return new Uint8Array(output.buffer, output.byteOffset, output.length);
    }
  };
}

/**
 * PRF(s, b, length) - SHAKE-256 with input s||b, output of given length.
 * @param {Uint8Array} s - seed
 * @param {number} b - domain separator byte
 * @param {number} length - output length in bytes
 * @returns {Uint8Array}
 */
export function PRF(s, b, length) {
  const input = new Uint8Array(s.length + 1);
  input.set(s);
  input[s.length] = b;
  const hash = createHash('shake256', { outputLength: length });
  hash.update(input);
  const digest = hash.digest();
  return new Uint8Array(digest.buffer, digest.byteOffset, digest.length);
}

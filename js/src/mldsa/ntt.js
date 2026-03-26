/**
 * Number Theoretic Transform for ML-DSA (FIPS 204)
 * Primitive 512th root of unity: zeta = 1753
 * Modulus Q = 8380417
 */

import { Q, modQ, fieldMul } from './field.js';

/**
 * Bit-reverse an 8-bit integer.
 * @param {number} x - value in [0, 255]
 * @returns {number}
 */
function bitRev8(x) {
  x = ((x & 0xF0) >>> 4) | ((x & 0x0F) << 4);
  x = ((x & 0xCC) >>> 2) | ((x & 0x33) << 2);
  x = ((x & 0xAA) >>> 1) | ((x & 0x55) << 1);
  return x;
}

/**
 * Modular exponentiation: base^exp mod Q
 */
function modPow(base, exp, mod) {
  let result = 1;
  base = ((base % mod) + mod) % mod;
  while (exp > 0) {
    if (exp & 1) {
      result = (result * base) % mod;
    }
    exp = exp >>> 1;
    base = (base * base) % mod;
  }
  return result;
}

/** Primitive 512th root of unity */
const ZETA = 1753;

/**
 * Precomputed zeta values: ZETAS[i] = zeta^(bitRev8(i)) mod Q
 * for i = 0..255
 */
export const ZETAS = new Int32Array(256);
for (let i = 0; i < 256; i++) {
  ZETAS[i] = modPow(ZETA, bitRev8(i), Q);
}

/** 256^{-1} mod Q = 8347681 */
const N_INV = 8347681;

/**
 * Forward NTT (in-place, Cooley-Tukey butterfly, 8 layers).
 * Transforms a polynomial of 256 coefficients.
 * @param {Int32Array} a - polynomial coefficients (modified in-place)
 * @returns {Int32Array} same array, now in NTT domain
 */
export function ntt(a) {
  let k = 0;
  for (let len = 128; len >= 1; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      k++;
      const z = ZETAS[k];
      for (let j = start; j < start + len; j++) {
        const t = fieldMul(z, modQ(a[j + len]));
        a[j + len] = modQ(a[j] - t);
        a[j] = modQ(a[j] + t);
      }
    }
  }
  return a;
}

/**
 * Inverse NTT (in-place, Gentleman-Sande butterfly, 8 layers).
 * Multiplies each coefficient by N_INV = 256^{-1} mod Q at the end.
 * @param {Int32Array} a - NTT-domain coefficients (modified in-place)
 * @returns {Int32Array} same array, now in normal domain
 */
export function invNtt(a) {
  let k = 256;
  for (let len = 1; len <= 128; len <<= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      k--;
      const z = Q - ZETAS[k];
      for (let j = start; j < start + len; j++) {
        const t = a[j];
        a[j] = modQ(t + a[j + len]);
        a[j + len] = fieldMul(z, modQ(t - a[j + len]));
      }
    }
  }
  for (let i = 0; i < 256; i++) {
    a[i] = fieldMul(a[i], N_INV);
  }
  return a;
}

/**
 * Element-wise multiplication in NTT domain.
 * @param {Int32Array} a - NTT-domain polynomial
 * @param {Int32Array} b - NTT-domain polynomial
 * @returns {Int32Array} new array with a[i]*b[i] mod Q
 */
export function pointwiseMul(a, b) {
  const c = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    c[i] = fieldMul(a[i], b[i]);
  }
  return c;
}

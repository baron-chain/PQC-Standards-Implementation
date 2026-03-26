/**
 * Number Theoretic Transform for ML-KEM (FIPS 203)
 * Implements Algorithms 9-12 from the specification.
 */

import { Q, mod, fieldMul, fieldAdd, fieldSub } from './field.js';

/**
 * Reverse the 7 least significant bits of n.
 * @param {number} n - integer in [0, 127]
 * @returns {number}
 */
export function bitRev7(n) {
  let result = 0;
  for (let i = 0; i < 7; i++) {
    result = (result << 1) | (n & 1);
    n >>= 1;
  }
  return result;
}

/**
 * Precomputed zeta values: ZETAS[i] = 17^(bitRev7(i)) mod Q for i in [0, 127].
 * 17 is a primitive 256th root of unity modulo Q=3329.
 */
export const ZETAS = (() => {
  const zetas = new Array(128);
  for (let i = 0; i < 128; i++) {
    const exp = bitRev7(i);
    // Compute 17^exp mod Q by repeated squaring
    let base = 17;
    let result = 1;
    let e = exp;
    while (e > 0) {
      if (e & 1) result = (result * base) % Q;
      base = (base * base) % Q;
      e >>= 1;
    }
    zetas[i] = result;
  }
  return zetas;
})();

/**
 * FIPS 203 Algorithm 9: NTT
 * Transforms a 256-element polynomial from normal to NTT domain.
 * @param {number[]} f - 256 coefficients
 * @returns {number[]} NTT representation
 */
export function ntt(f) {
  const fHat = f.slice();
  let i = 1;
  for (let len = 128; len >= 2; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[i++];
      for (let j = start; j < start + len; j++) {
        const t = (zeta * fHat[j + len]) % Q;
        fHat[j + len] = (fHat[j] - t + Q) % Q;
        fHat[j] = (fHat[j] + t) % Q;
      }
    }
  }
  return fHat;
}

/**
 * FIPS 203 Algorithm 10: NTT Inverse
 * Transforms from NTT domain back to normal domain.
 * Final multiplication by 3303 = 128^(-1) mod Q.
 * @param {number[]} fHat - 256 NTT coefficients
 * @returns {number[]} normal domain polynomial
 */
export function nttInverse(fHat) {
  const f = fHat.slice();
  let i = 127;
  for (let len = 2; len <= 128; len <<= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[i--];
      for (let j = start; j < start + len; j++) {
        const t = f[j];
        f[j] = (t + f[j + len]) % Q;
        f[j + len] = (zeta * (f[j + len] - t + Q)) % Q;
      }
    }
  }
  // Multiply every coefficient by 128^(-1) mod Q = 3303
  const inv128 = 3303;
  for (let j = 0; j < 256; j++) {
    f[j] = (f[j] * inv128) % Q;
  }
  return f;
}

/**
 * FIPS 203 Algorithm 12: BaseCaseMultiply
 * Multiplies two degree-1 polynomials modulo X^2 - gamma.
 * @param {number} a0
 * @param {number} a1
 * @param {number} b0
 * @param {number} b1
 * @param {number} gamma - the zeta value for this pair
 * @returns {number[]} [c0, c1]
 */
export function baseCaseMultiply(a0, a1, b0, b1, gamma) {
  const c0 = (fieldMul(a0, b0) + fieldMul(fieldMul(a1, b1), gamma)) % Q;
  const c1 = (fieldMul(a0, b1) + fieldMul(a1, b0)) % Q;
  return [c0, c1];
}

/**
 * FIPS 203 Algorithm 11: MultiplyNTTs
 * Pointwise multiplication of two NTT-domain polynomials using baseCaseMultiply.
 * @param {number[]} fHat - 256 NTT coefficients
 * @param {number[]} gHat - 256 NTT coefficients
 * @returns {number[]} product in NTT domain
 */
export function multiplyNTTs(fHat, gHat) {
  const hHat = new Array(256);
  for (let i = 0; i < 64; i++) {
    const gamma0 = ZETAS[64 + i];
    const [c0, c1] = baseCaseMultiply(
      fHat[4 * i], fHat[4 * i + 1],
      gHat[4 * i], gHat[4 * i + 1],
      gamma0
    );
    hHat[4 * i] = c0;
    hHat[4 * i + 1] = c1;

    // Negative gamma for the second pair
    const gamma1 = (Q - gamma0) % Q;
    const [d0, d1] = baseCaseMultiply(
      fHat[4 * i + 2], fHat[4 * i + 3],
      gHat[4 * i + 2], gHat[4 * i + 3],
      gamma1
    );
    hHat[4 * i + 2] = d0;
    hHat[4 * i + 3] = d1;
  }
  return hHat;
}

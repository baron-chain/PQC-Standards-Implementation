/**
 * Sampling functions for ML-KEM (FIPS 203)
 * Implements Algorithms 7 and 8.
 */

import { Q } from './field.js';

/**
 * FIPS 203 Algorithm 7: SampleNTT
 * Rejection sampling from a byte stream to produce a polynomial in NTT domain.
 * Reads 3 bytes at a time, extracts two 12-bit candidate values,
 * accepts each if < Q=3329. Produces exactly 256 coefficients.
 *
 * @param {Uint8Array} xofOutput - at least 672 bytes from SHAKE-128
 * @returns {number[]} 256 coefficients in [0, Q)
 */
export function sampleNTT(xofOutput) {
  const a = new Array(256);
  let j = 0;  // number of accepted coefficients
  let i = 0;  // byte index

  while (j < 256) {
    if (i + 2 >= xofOutput.length) {
      throw new Error('SampleNTT: insufficient XOF output bytes');
    }
    const b0 = xofOutput[i];
    const b1 = xofOutput[i + 1];
    const b2 = xofOutput[i + 2];
    i += 3;

    const d1 = ((b1 & 0x0F) << 8) | b0;   // lower 12 bits
    const d2 = (b2 << 4) | (b1 >> 4);       // upper 12 bits

    if (d1 < Q) {
      a[j] = d1;
      j++;
    }
    if (j < 256 && d2 < Q) {
      a[j] = d2;
      j++;
    }
  }

  return a;
}

/**
 * FIPS 203 Algorithm 8: SamplePolyCBD_eta
 * Centered binomial distribution sampling.
 *
 * For eta=2: each coefficient uses 4 bits (2+2); process 1 byte per 2 coefficients.
 *            Total bytes needed: 64*eta = 128
 * For eta=3: each coefficient uses 6 bits (3+3); process at bit level.
 *            Total bytes needed: 64*eta = 192
 *
 * @param {Uint8Array} bytes - 64*eta bytes of pseudorandom input
 * @param {number} eta - 2 or 3
 * @returns {number[]} 256 coefficients in [0, Q) (centered, reduced mod Q)
 */
export function samplePolyCBD(bytes, eta) {
  const f = new Array(256);

  if (eta === 2) {
    // 64*2 = 128 bytes, 1 byte per 2 coefficients
    for (let i = 0; i < 256; i += 2) {
      const b = bytes[i >> 1];
      // First coefficient: bits [0,1] - bits [2,3]
      const x0 = (b & 1) + ((b >> 1) & 1);
      const y0 = ((b >> 2) & 1) + ((b >> 3) & 1);
      f[i] = (x0 - y0 + Q) % Q;

      // Second coefficient: bits [4,5] - bits [6,7]
      const x1 = ((b >> 4) & 1) + ((b >> 5) & 1);
      const y1 = ((b >> 6) & 1) + ((b >> 7) & 1);
      f[i + 1] = (x1 - y1 + Q) % Q;
    }
  } else if (eta === 3) {
    // 64*3 = 192 bytes, process at bit level
    // Each coefficient uses 6 bits: 3 for x, 3 for y
    for (let i = 0; i < 256; i++) {
      const bitOffset = i * 6;
      let x = 0;
      let y = 0;
      for (let j = 0; j < 3; j++) {
        const bpos = bitOffset + j;
        x += (bytes[bpos >> 3] >> (bpos & 7)) & 1;
      }
      for (let j = 0; j < 3; j++) {
        const bpos = bitOffset + 3 + j;
        y += (bytes[bpos >> 3] >> (bpos & 7)) & 1;
      }
      f[i] = (x - y + Q) % Q;
    }
  } else {
    throw new RangeError('eta must be 2 or 3');
  }

  return f;
}

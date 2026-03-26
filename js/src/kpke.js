/**
 * K-PKE: Encryption scheme underlying ML-KEM (FIPS 203)
 * Implements Algorithms 13, 14, and 15.
 */

import { Q, mod, fieldAdd, fieldSub, fieldMul } from './field.js';
import { ntt, nttInverse, multiplyNTTs } from './ntt.js';
import { byteEncode, byteDecode } from './encode.js';
import { compressPoly, decompressPoly } from './compress.js';
import { G, XOF, PRF } from './hash.js';
import { sampleNTT, samplePolyCBD } from './sampling.js';

/**
 * Add two polynomials coefficient-wise mod Q.
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number[]}
 */
function polyAdd(a, b) {
  const c = new Array(256);
  for (let i = 0; i < 256; i++) {
    c[i] = (a[i] + b[i]) % Q;
  }
  return c;
}

/**
 * Subtract two polynomials coefficient-wise mod Q.
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number[]}
 */
function polySub(a, b) {
  const c = new Array(256);
  for (let i = 0; i < 256; i++) {
    c[i] = (a[i] - b[i] + Q) % Q;
  }
  return c;
}

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
 * FIPS 203 Algorithm 13: K-PKE.KeyGen(d)
 *
 * @param {Uint8Array} d - 32-byte random seed
 * @param {object} params - ML-KEM parameter set
 * @returns {{ ekPKE: Uint8Array, dkPKE: Uint8Array }}
 */
export function kpkeKeyGen(d, params) {
  const { k, eta1 } = params;

  // Step 1: (rho, sigma) = G(d || k)
  const dWithK = new Uint8Array(d.length + 1);
  dWithK.set(d);
  dWithK[d.length] = k;
  const { rho, sigma } = G(dWithK);

  // Step 2-4: Generate matrix A^ (in NTT domain) from rho
  const AHat = [];
  for (let i = 0; i < k; i++) {
    AHat[i] = [];
    for (let j = 0; j < k; j++) {
      const xof = XOF(rho, i, j);
      AHat[i][j] = sampleNTT(xof.bytes());
    }
  }

  // Step 5-7: Generate secret vector s (in normal domain, then NTT)
  let N = 0;
  const sHat = [];
  for (let i = 0; i < k; i++) {
    const prfBytes = PRF(sigma, N, 64 * eta1);
    N++;
    const si = samplePolyCBD(prfBytes, eta1);
    sHat[i] = ntt(si);
  }

  // Step 8-10: Generate error vector e (in normal domain, then NTT)
  const eHat = [];
  for (let i = 0; i < k; i++) {
    const prfBytes = PRF(sigma, N, 64 * eta1);
    N++;
    const ei = samplePolyCBD(prfBytes, eta1);
    eHat[i] = ntt(ei);
  }

  // Step 11: t^ = A^ * s^ + e^
  const tHat = [];
  for (let i = 0; i < k; i++) {
    let acc = new Array(256).fill(0);
    for (let j = 0; j < k; j++) {
      acc = polyAdd(acc, multiplyNTTs(AHat[i][j], sHat[j]));
    }
    tHat[i] = polyAdd(acc, eHat[i]);
  }

  // Step 12: Encode ekPKE = ByteEncode12(t^[0]) || ... || ByteEncode12(t^[k-1]) || rho
  const ekParts = [];
  for (let i = 0; i < k; i++) {
    ekParts.push(byteEncode(12, tHat[i]));
  }
  ekParts.push(rho);
  const ekPKE = concatBytes(...ekParts);

  // Step 13: Encode dkPKE = ByteEncode12(s^[0]) || ... || ByteEncode12(s^[k-1])
  const dkParts = [];
  for (let i = 0; i < k; i++) {
    dkParts.push(byteEncode(12, sHat[i]));
  }
  const dkPKE = concatBytes(...dkParts);

  return { ekPKE, dkPKE };
}

/**
 * FIPS 203 Algorithm 14: K-PKE.Encrypt(ekPKE, m, r)
 *
 * @param {Uint8Array} ekPKE - encryption key from kpkeKeyGen
 * @param {Uint8Array} m - 32-byte message (shared secret to encapsulate)
 * @param {Uint8Array} r - 32-byte randomness (deterministic for ML-KEM)
 * @param {object} params - ML-KEM parameter set
 * @returns {Uint8Array} ciphertext c
 */
export function kpkeEncrypt(ekPKE, m, r, params) {
  const { k, eta1, eta2, du, dv } = params;

  // Step 1: Decode t^ from ekPKE
  const tHat = [];
  for (let i = 0; i < k; i++) {
    const slice = ekPKE.slice(i * 384, (i + 1) * 384);
    tHat[i] = byteDecode(12, slice).map(c => c % Q);
  }
  const rho = ekPKE.slice(k * 384, k * 384 + 32);

  // Step 2: Generate A^ from rho (transposed: A^[j][i] for encrypt)
  const AHat = [];
  for (let i = 0; i < k; i++) {
    AHat[i] = [];
    for (let j = 0; j < k; j++) {
      const xof = XOF(rho, i, j);
      AHat[i][j] = sampleNTT(xof.bytes());
    }
  }

  // Step 3-5: Sample r vector
  let N = 0;
  const rVecHat = [];
  for (let i = 0; i < k; i++) {
    const prfBytes = PRF(r, N, 64 * eta1);
    N++;
    const ri = samplePolyCBD(prfBytes, eta1);
    rVecHat[i] = ntt(ri);
  }

  // Step 6-8: Sample e1 vector
  const e1 = [];
  for (let i = 0; i < k; i++) {
    const prfBytes = PRF(r, N, 64 * eta2);
    N++;
    e1[i] = samplePolyCBD(prfBytes, eta2);
  }

  // Step 9: Sample e2 scalar
  const e2Bytes = PRF(r, N, 64 * eta2);
  N++;
  const e2 = samplePolyCBD(e2Bytes, eta2);

  // Step 10: u = NTT^-1(A^T * r^) + e1
  // A^T[i][j] = A^[j][i]
  const u = [];
  for (let i = 0; i < k; i++) {
    let acc = new Array(256).fill(0);
    for (let j = 0; j < k; j++) {
      // A^T[i][j] = A^[j][i]
      acc = polyAdd(acc, multiplyNTTs(AHat[j][i], rVecHat[j]));
    }
    u[i] = polyAdd(nttInverse(acc), e1[i]);
  }

  // Step 11: Decode message as polynomial
  const mu = byteDecode(1, m);

  // Step 12: v = NTT^-1(t^ . r^) + e2 + Decompress_1(mu)
  let tDotR = new Array(256).fill(0);
  for (let i = 0; i < k; i++) {
    tDotR = polyAdd(tDotR, multiplyNTTs(tHat[i], rVecHat[i]));
  }
  let v = nttInverse(tDotR);
  v = polyAdd(v, e2);
  // Decompress_1(mu): each bit b maps to round(Q/2) * b
  const decompMu = new Array(256);
  for (let i = 0; i < 256; i++) {
    decompMu[i] = mu[i] === 0 ? 0 : Math.round(Q / 2);
  }
  v = polyAdd(v, decompMu);

  // Step 13-14: Compress and encode
  const c1Parts = [];
  for (let i = 0; i < k; i++) {
    const compressed = compressPoly(du, u[i]);
    c1Parts.push(byteEncode(du, compressed));
  }
  const c1 = concatBytes(...c1Parts);

  const compressedV = compressPoly(dv, v);
  const c2 = byteEncode(dv, compressedV);

  return concatBytes(c1, c2);
}

/**
 * FIPS 203 Algorithm 15: K-PKE.Decrypt(dkPKE, c)
 *
 * @param {Uint8Array} dkPKE - decryption key from kpkeKeyGen
 * @param {Uint8Array} c - ciphertext
 * @param {object} params - ML-KEM parameter set
 * @returns {Uint8Array} 32-byte message m
 */
export function kpkeDecrypt(dkPKE, c, params) {
  const { k, du, dv } = params;

  // Step 1-2: Decode and decompress u from c
  const c1Len = k * 32 * du;
  const u = [];
  for (let i = 0; i < k; i++) {
    const slice = c.slice(i * 32 * du, (i + 1) * 32 * du);
    const decoded = byteDecode(du, slice);
    u[i] = decompressPoly(du, decoded);
  }

  // Step 3: Decode and decompress v from c
  const c2 = c.slice(c1Len);
  const decodedV = byteDecode(dv, c2);
  const v = decompressPoly(dv, decodedV);

  // Step 4: Decode s^ from dkPKE
  const sHat = [];
  for (let i = 0; i < k; i++) {
    const slice = dkPKE.slice(i * 384, (i + 1) * 384);
    sHat[i] = byteDecode(12, slice).map(c => c % Q);
  }

  // Step 5: w = v - NTT^-1(s^ . NTT(u))
  let sDotU = new Array(256).fill(0);
  for (let i = 0; i < k; i++) {
    const uHat = ntt(u[i]);
    sDotU = polyAdd(sDotU, multiplyNTTs(sHat[i], uHat));
  }
  const w = polySub(v, nttInverse(sDotU));

  // Step 6: Compress_1(w) and encode as message
  const mPoly = compressPoly(1, w);
  return byteEncode(1, mPoly);
}

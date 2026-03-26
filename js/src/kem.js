/**
 * ML-KEM: Key Encapsulation Mechanism (FIPS 203)
 * Implements Algorithms 16, 17, and 18.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { Q } from './field.js';
import { byteDecode } from './encode.js';
import { H, G, J } from './hash.js';
import { kpkeKeyGen, kpkeEncrypt, kpkeDecrypt } from './kpke.js';

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
 * Validate an encapsulation key: all decoded 12-bit coefficients must be < Q.
 * FIPS 203 Section 7.2: Type check on encapsulation key.
 *
 * @param {Uint8Array} ek - encapsulation key
 * @param {object} params
 * @returns {boolean} true if valid
 */
function validateEk(ek, params) {
  const { k } = params;
  for (let i = 0; i < k; i++) {
    const slice = ek.slice(i * 384, (i + 1) * 384);
    const coeffs = byteDecode(12, slice);
    for (let j = 0; j < 256; j++) {
      if (coeffs[j] >= Q) return false;
    }
  }
  return true;
}

/**
 * FIPS 203 Algorithm 16: ML-KEM.KeyGen
 * Generates an ML-KEM key pair.
 *
 * @param {object} params - ML-KEM parameter set (ML_KEM_512, ML_KEM_768, ML_KEM_1024)
 * @returns {{ ek: Uint8Array, dk: Uint8Array }}
 */
export function keyGen(params) {
  const { k } = params;

  // Step 1-2: Generate random seeds
  const d = randomBytes(32);
  const z = randomBytes(32);

  // Step 3: Generate K-PKE key pair
  const { ekPKE, dkPKE } = kpkeKeyGen(new Uint8Array(d), params);

  // Step 4: ek = ekPKE
  const ek = ekPKE;

  // Step 5: dk = dkPKE || ek || H(ek) || z
  const hEk = H(ek);
  const dk = concatBytes(dkPKE, ek, hEk, new Uint8Array(z));

  return { ek, dk };
}

/**
 * FIPS 203 Algorithm 17: ML-KEM.Encaps
 * Encapsulates a shared key using the encapsulation key.
 *
 * @param {Uint8Array} ek - encapsulation key
 * @param {object} params - ML-KEM parameter set
 * @returns {{ K: Uint8Array, c: Uint8Array }}
 */
export function encaps(ek, params) {
  // Validate encapsulation key
  if (!validateEk(ek, params)) {
    throw new Error('ML-KEM.Encaps: invalid encapsulation key');
  }

  // Step 1: m = random 32 bytes
  const m = randomBytes(32);

  // Step 2: (K, r) = G(m || H(ek))
  const hEk = H(ek);
  const { rho: K, sigma: r } = G(concatBytes(new Uint8Array(m), hEk));

  // Step 3: c = K-PKE.Encrypt(ek, m, r)
  const c = kpkeEncrypt(ek, new Uint8Array(m), r, params);

  return { K, c };
}

/**
 * FIPS 203 Algorithm 18: ML-KEM.Decaps
 * Decapsulates to recover the shared key.
 * Uses implicit rejection: if re-encryption doesn't match,
 * returns J(z || c) instead.
 *
 * @param {Uint8Array} dk - decapsulation key
 * @param {Uint8Array} c - ciphertext
 * @param {object} params - ML-KEM parameter set
 * @returns {Uint8Array} shared key K (32 bytes)
 */
export function decaps(dk, c, params) {
  const { k } = params;

  // Parse dk = dkPKE || ekPKE || h || z
  const dkPKELen = k * 384;
  const ekPKELen = k * 384 + 32;

  const dkPKE = dk.slice(0, dkPKELen);
  const ekPKE = dk.slice(dkPKELen, dkPKELen + ekPKELen);
  const h = dk.slice(dkPKELen + ekPKELen, dkPKELen + ekPKELen + 32);
  const z = dk.slice(dkPKELen + ekPKELen + 32, dkPKELen + ekPKELen + 64);

  // Step 1: m' = K-PKE.Decrypt(dkPKE, c)
  const mPrime = kpkeDecrypt(dkPKE, c, params);

  // Step 2: (K', r') = G(m' || h)
  const { rho: KPrime, sigma: rPrime } = G(concatBytes(mPrime, h));

  // Step 3: K_bar = J(z || c) -- implicit rejection key
  const KBar = J(concatBytes(z, c));

  // Step 4: c' = K-PKE.Encrypt(ekPKE, m', r')
  const cPrime = kpkeEncrypt(ekPKE, mPrime, rPrime, params);

  // Step 5: Constant-time comparison
  // If c == c', return K'; otherwise return K_bar (implicit rejection)
  let match;
  try {
    match = timingSafeEqual(c, cPrime);
  } catch {
    // timingSafeEqual throws if lengths differ
    match = false;
  }

  // Constant-time select: return K' if match, K_bar otherwise
  // Using a constant-time approach
  const K = new Uint8Array(32);
  const mask = match ? 0xFF : 0x00;
  const nmask = ~mask & 0xFF;
  for (let i = 0; i < 32; i++) {
    K[i] = (KPrime[i] & mask) | (KBar[i] & nmask);
  }

  return K;
}

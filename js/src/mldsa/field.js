/**
 * Field arithmetic for ML-DSA (FIPS 204)
 * All operations in Z_Q where Q = 8380417
 */

/** The ML-DSA prime modulus */
export const Q = 8380417;

/**
 * Modular reduction that always returns a non-negative result in [0, Q).
 * @param {number} a - integer
 * @returns {number} a mod Q, always >= 0
 */
export function modQ(a) {
  const r = a % Q;
  return r < 0 ? r + Q : r;
}

/**
 * Field addition: (a + b) mod Q
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function fieldAdd(a, b) {
  return modQ(a + b);
}

/**
 * Field subtraction: (a - b) mod Q
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function fieldSub(a, b) {
  return modQ(a - b);
}

/**
 * Field multiplication: (a * b) mod Q
 * Since Q < 2^23, the product a*b < 2^46 which is within
 * the safe integer range of 2^53 for JavaScript.
 * @param {number} a - value in [0, Q)
 * @param {number} b - value in [0, Q)
 * @returns {number}
 */
export function fieldMul(a, b) {
  return modQ(a * b);
}

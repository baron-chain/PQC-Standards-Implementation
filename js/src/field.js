/**
 * Field arithmetic for ML-KEM (FIPS 203)
 * All operations in Z_Q where Q = 3329
 */

/** The ML-KEM prime modulus */
export const Q = 3329;

/**
 * Modular reduction that always returns a non-negative result in [0, q).
 * @param {number} a - integer
 * @param {number} q - modulus
 * @returns {number} a mod q, always >= 0
 */
export function mod(a, q) {
  const r = a % q;
  return r < 0 ? r + q : (r === 0 ? 0 : r);
}

/**
 * Field addition: (a + b) mod Q
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function fieldAdd(a, b) {
  return (a + b) % Q;
}

/**
 * Field subtraction: (a - b + Q) mod Q
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function fieldSub(a, b) {
  return (a - b + Q) % Q;
}

/**
 * Field multiplication: (a * b) mod Q
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function fieldMul(a, b) {
  return mod(a * b, Q);
}

/**
 * Modular exponentiation: base^exp mod Q
 * Uses square-and-multiply. All intermediate values stay in safe integer range
 * since Q=3329 means max intermediate is (Q-1)^2 = ~11M, well within 2^53.
 * @param {number} base
 * @param {number} exp - non-negative integer
 * @returns {number}
 */
export function fieldPow(base, exp) {
  if (exp < 0) throw new RangeError('exponent must be non-negative');
  base = mod(base, Q);
  let result = 1;
  while (exp > 0) {
    if (exp & 1) {
      result = (result * base) % Q;
    }
    base = (base * base) % Q;
    exp >>= 1;
  }
  return result;
}

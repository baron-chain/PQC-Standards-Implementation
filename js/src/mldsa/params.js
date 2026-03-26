/**
 * ML-DSA parameter sets (FIPS 204, Table 1)
 */

/**
 * ML-DSA-44: NIST security level 2
 */
export const ML_DSA_44 = {
  name: 'ML-DSA-44',
  k: 4,
  l: 4,
  eta: 2,
  tau: 39,
  beta: 78,
  gamma1: (1 << 17),       // 2^17 = 131072
  gamma2: 95232,            // (Q-1)/88
  omega: 80,
  lambda: 128,
  sigSize: 2420,
  pkSize: 1312,
  skSize: 2560,
};

/**
 * ML-DSA-65: NIST security level 3
 */
export const ML_DSA_65 = {
  name: 'ML-DSA-65',
  k: 6,
  l: 5,
  eta: 4,
  tau: 49,
  beta: 196,
  gamma1: (1 << 19),       // 2^19 = 524288
  gamma2: 261888,           // (Q-1)/32
  omega: 55,
  lambda: 192,
  sigSize: 3309,
  pkSize: 1952,
  skSize: 4032,
};

/**
 * ML-DSA-87: NIST security level 5
 */
export const ML_DSA_87 = {
  name: 'ML-DSA-87',
  k: 8,
  l: 7,
  eta: 2,
  tau: 60,
  beta: 120,
  gamma1: (1 << 19),       // 2^19 = 524288
  gamma2: 261888,           // (Q-1)/32
  omega: 75,
  lambda: 256,
  sigSize: 4627,
  pkSize: 2592,
  skSize: 4896,
};

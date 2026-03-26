/**
 * ML-KEM parameter sets (FIPS 203, Table 1)
 */

/**
 * ML-KEM-512: NIST security level 1
 */
export const ML_KEM_512 = {
  name: 'ML-KEM-512',
  k: 2,
  eta1: 3,
  eta2: 2,
  du: 10,
  dv: 4,
  ekSize: 384 * 2 + 32,      // 800
  dkSize: 768 * 2 + 96,      // 1632
  ctSize: 32 * (10 * 2 + 4), // 768
};

/**
 * ML-KEM-768: NIST security level 3
 */
export const ML_KEM_768 = {
  name: 'ML-KEM-768',
  k: 3,
  eta1: 2,
  eta2: 2,
  du: 10,
  dv: 4,
  ekSize: 384 * 3 + 32,      // 1184
  dkSize: 768 * 3 + 96,      // 2400
  ctSize: 32 * (10 * 3 + 4), // 1088
};

/**
 * ML-KEM-1024: NIST security level 5
 */
export const ML_KEM_1024 = {
  name: 'ML-KEM-1024',
  k: 4,
  eta1: 2,
  eta2: 2,
  du: 11,
  dv: 5,
  ekSize: 384 * 4 + 32,      // 1568
  dkSize: 768 * 4 + 96,      // 3168
  ctSize: 32 * (11 * 4 + 5), // 1568
};

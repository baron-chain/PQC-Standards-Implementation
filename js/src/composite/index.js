/**
 * Composite Signature Schemes — ML-DSA + classical signatures.
 */

export {
  keyGen,
  sign,
  verify,
  MLDSA65_ED25519,
  MLDSA65_ECDSA_P256,
  MLDSA87_ED25519,
  MLDSA44_ED25519,
} from './composite_sig.js';

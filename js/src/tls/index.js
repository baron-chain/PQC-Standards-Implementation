/**
 * PQC TLS 1.3 Integration Layer
 *
 * Provides PQC key exchange and signature components for TLS 1.3 handshakes.
 */

export {
  NamedGroup,
  ALL_NAMED_GROUPS,
  namedGroupName,
  namedGroupFromCodePoint,
  generateKeyShare,
  completeKeyExchange,
  recoverSharedSecret,
  keyShareSize,
} from './named_groups.js';

export {
  SignatureAlgorithm,
  ALL_SIGNATURE_ALGORITHMS,
  signatureAlgorithmName,
  signatureAlgorithmFromCodePoint,
  isComposite,
  generateSigningKey,
  signHandshake,
  verifyHandshake,
} from './sig_algorithms.js';

export {
  AeadAlgorithm,
  aeadKeyLength,
  aeadHashLength,
  TLS_AES_128_GCM_SHA256_MLKEM768,
  TLS_AES_256_GCM_SHA384_X25519MLKEM768,
  ALL_CIPHER_SUITES,
  cipherSuiteById,
} from './cipher_suites.js';

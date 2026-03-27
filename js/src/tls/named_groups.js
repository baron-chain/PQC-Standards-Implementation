/**
 * PQC Named Groups for TLS 1.3 key exchange.
 *
 * Defines PQC and hybrid named groups for the `supported_groups` extension
 * (ClientHello/ServerHello), along with key share generation and exchange
 * completion helpers.
 */

import { keyGen as mlkemKeyGen, encaps as mlkemEncaps, decaps as mlkemDecaps } from '../kem.js';
import { ML_KEM_768, ML_KEM_1024 } from '../params.js';
import {
  HYBRID_X25519_MLKEM768,
  HYBRID_ECDHP256_MLKEM768,
  hybridKeyGen, hybridEncaps, hybridDecaps,
} from '../hybrid/hybrid_kem.js';

/** TLS 1.3 named group code points for PQC key exchange. */
export const NamedGroup = Object.freeze({
  MLKEM768:          0x0768,
  MLKEM1024:         0x1024,
  X25519MLKEM768:    0x6399,
  SecP256r1MLKEM768: 0x639A,
});

/** All defined named groups. */
export const ALL_NAMED_GROUPS = Object.freeze([
  NamedGroup.MLKEM768,
  NamedGroup.MLKEM1024,
  NamedGroup.X25519MLKEM768,
  NamedGroup.SecP256r1MLKEM768,
]);

/** Human-readable names. */
export function namedGroupName(groupId) {
  switch (groupId) {
    case NamedGroup.MLKEM768: return 'MLKEM768';
    case NamedGroup.MLKEM1024: return 'MLKEM1024';
    case NamedGroup.X25519MLKEM768: return 'X25519MLKEM768';
    case NamedGroup.SecP256r1MLKEM768: return 'SecP256r1MLKEM768';
    default: return 'Unknown';
  }
}

/** Look up a named group by code point. Returns undefined if not found. */
export function namedGroupFromCodePoint(cp) {
  if (ALL_NAMED_GROUPS.includes(cp)) return cp;
  return undefined;
}

function mlkemParams(groupId) {
  switch (groupId) {
    case NamedGroup.MLKEM768: return ML_KEM_768;
    case NamedGroup.MLKEM1024: return ML_KEM_1024;
    default: throw new Error('Not a pure ML-KEM group');
  }
}

function hybridScheme(groupId) {
  switch (groupId) {
    case NamedGroup.X25519MLKEM768: return HYBRID_X25519_MLKEM768;
    case NamedGroup.SecP256r1MLKEM768: return HYBRID_ECDHP256_MLKEM768;
    default: throw new Error('Not a hybrid group');
  }
}

/**
 * Generate a key share for the given named group.
 *
 * @param {number} groupId - Named group code point
 * @returns {{ privateKey: Uint8Array, publicKeyShare: Uint8Array, classicalEkSize: number, classicalDkSize: number }}
 */
export function generateKeyShare(groupId) {
  switch (groupId) {
    case NamedGroup.MLKEM768:
    case NamedGroup.MLKEM1024: {
      const params = mlkemParams(groupId);
      const { ek, dk } = mlkemKeyGen(params);
      return {
        privateKey: dk,
        publicKeyShare: ek,
        classicalEkSize: 0,
        classicalDkSize: 0,
      };
    }
    case NamedGroup.X25519MLKEM768:
    case NamedGroup.SecP256r1MLKEM768: {
      const scheme = hybridScheme(groupId);
      const kp = hybridKeyGen(scheme);
      return {
        privateKey: kp.dk,
        publicKeyShare: kp.ek,
        classicalEkSize: kp.classicalEkSize,
        classicalDkSize: kp.classicalDkSize,
      };
    }
    default:
      throw new Error(`Unsupported named group: 0x${groupId.toString(16)}`);
  }
}

/**
 * Complete a key exchange as the responder (ServerHello side).
 *
 * @param {number} groupId
 * @param {Uint8Array} peerKeyShare
 * @param {number} classicalEkSize - For hybrid groups
 * @returns {{ sharedSecret: Uint8Array, responseKeyShare: Uint8Array, classicalCtSize: number }}
 */
export function completeKeyExchange(groupId, peerKeyShare, classicalEkSize = 0) {
  switch (groupId) {
    case NamedGroup.MLKEM768:
    case NamedGroup.MLKEM1024: {
      const params = mlkemParams(groupId);
      const { K, c } = mlkemEncaps(peerKeyShare, params);
      return {
        sharedSecret: K,
        responseKeyShare: c,
        classicalCtSize: 0,
      };
    }
    case NamedGroup.X25519MLKEM768:
    case NamedGroup.SecP256r1MLKEM768: {
      const scheme = hybridScheme(groupId);
      const result = hybridEncaps(scheme, peerKeyShare, classicalEkSize);
      return {
        sharedSecret: result.sharedSecret,
        responseKeyShare: result.ciphertext,
        classicalCtSize: result.classicalCtSize,
      };
    }
    default:
      throw new Error(`Unsupported named group: 0x${groupId.toString(16)}`);
  }
}

/**
 * Recover the shared secret as the initiator (ClientHello side).
 *
 * @param {number} groupId
 * @param {Uint8Array} privateKey
 * @param {Uint8Array} peerResponse
 * @param {number} classicalDkSize
 * @param {number} classicalCtSize
 * @returns {Uint8Array} 32-byte shared secret
 */
export function recoverSharedSecret(groupId, privateKey, peerResponse, classicalDkSize = 0, classicalCtSize = 0) {
  switch (groupId) {
    case NamedGroup.MLKEM768:
    case NamedGroup.MLKEM1024: {
      const params = mlkemParams(groupId);
      return mlkemDecaps(privateKey, peerResponse, params);
    }
    case NamedGroup.X25519MLKEM768:
    case NamedGroup.SecP256r1MLKEM768: {
      const scheme = hybridScheme(groupId);
      return hybridDecaps(scheme, privateKey, peerResponse, classicalDkSize, classicalCtSize);
    }
    default:
      throw new Error(`Unsupported named group: 0x${groupId.toString(16)}`);
  }
}

/**
 * Expected public key share size for a named group.
 * @param {number} groupId
 * @returns {number}
 */
export function keyShareSize(groupId) {
  switch (groupId) {
    case NamedGroup.MLKEM768: return ML_KEM_768.ekSize;
    case NamedGroup.MLKEM1024: return ML_KEM_1024.ekSize;
    case NamedGroup.X25519MLKEM768: return 32 + ML_KEM_768.ekSize;
    case NamedGroup.SecP256r1MLKEM768: return 65 + ML_KEM_768.ekSize;
    default: return 0;
  }
}

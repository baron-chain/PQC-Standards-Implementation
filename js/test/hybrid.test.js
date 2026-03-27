import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  hybridKeyGen,
  hybridEncaps,
  hybridDecaps,
  HYBRID_X25519_MLKEM768,
  HYBRID_ECDHP256_MLKEM768,
  HYBRID_X25519_MLKEM1024,
  HYBRID_ECDHP384_MLKEM1024,
} from '../src/hybrid/hybrid_kem.js';

function roundtripTest(scheme) {
  const kp = hybridKeyGen(scheme);
  const enc = hybridEncaps(scheme, kp.ek, kp.classicalEkSize);
  const ss = hybridDecaps(scheme, kp.dk, enc.ciphertext, kp.classicalDkSize, enc.classicalCtSize);

  assert.equal(enc.sharedSecret.length, 32, 'shared secret should be 32 bytes');
  assert.deepStrictEqual(enc.sharedSecret, ss, `${scheme.name} roundtrip failed`);
}

describe('Hybrid KEM', () => {
  describe('X25519 + ML-KEM-768', () => {
    it('should complete roundtrip correctly', () => {
      roundtripTest(HYBRID_X25519_MLKEM768);
    });
  });

  describe('ECDH-P256 + ML-KEM-768', () => {
    it('should complete roundtrip correctly', () => {
      roundtripTest(HYBRID_ECDHP256_MLKEM768);
    });
  });

  describe('X25519 + ML-KEM-1024', () => {
    it('should complete roundtrip correctly', () => {
      roundtripTest(HYBRID_X25519_MLKEM1024);
    });
  });

  describe('ECDH-P384 + ML-KEM-1024', () => {
    it('should complete roundtrip correctly', () => {
      roundtripTest(HYBRID_ECDHP384_MLKEM1024);
    });
  });

  describe('Security properties', () => {
    it('should produce different secrets for different keys', () => {
      const kp1 = hybridKeyGen(HYBRID_X25519_MLKEM768);
      const kp2 = hybridKeyGen(HYBRID_X25519_MLKEM768);
      const enc1 = hybridEncaps(HYBRID_X25519_MLKEM768, kp1.ek, kp1.classicalEkSize);
      const enc2 = hybridEncaps(HYBRID_X25519_MLKEM768, kp2.ek, kp2.classicalEkSize);
      assert.notDeepStrictEqual(enc1.sharedSecret, enc2.sharedSecret);
    });

    it('should produce different secrets for multiple encapsulations with same key', () => {
      const kp = hybridKeyGen(HYBRID_X25519_MLKEM768);
      const enc1 = hybridEncaps(HYBRID_X25519_MLKEM768, kp.ek, kp.classicalEkSize);
      const enc2 = hybridEncaps(HYBRID_X25519_MLKEM768, kp.ek, kp.classicalEkSize);
      assert.notDeepStrictEqual(enc1.sharedSecret, enc2.sharedSecret);

      // Both should still roundtrip
      const ss1 = hybridDecaps(HYBRID_X25519_MLKEM768, kp.dk, enc1.ciphertext, kp.classicalDkSize, enc1.classicalCtSize);
      const ss2 = hybridDecaps(HYBRID_X25519_MLKEM768, kp.dk, enc2.ciphertext, kp.classicalDkSize, enc2.classicalCtSize);
      assert.deepStrictEqual(enc1.sharedSecret, ss1);
      assert.deepStrictEqual(enc2.sharedSecret, ss2);
    });
  });
});

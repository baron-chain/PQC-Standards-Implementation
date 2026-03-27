/**
 * Tests for the PQC TLS 1.3 integration layer.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  NamedGroup,
  ALL_NAMED_GROUPS,
  namedGroupName,
  namedGroupFromCodePoint,
  generateKeyShare,
  completeKeyExchange,
  recoverSharedSecret,
  keyShareSize,
  SignatureAlgorithm,
  ALL_SIGNATURE_ALGORITHMS,
  signatureAlgorithmName,
  signatureAlgorithmFromCodePoint,
  isComposite,
  generateSigningKey,
  signHandshake,
  verifyHandshake,
  AeadAlgorithm,
  TLS_AES_128_GCM_SHA256_MLKEM768,
  TLS_AES_256_GCM_SHA384_X25519MLKEM768,
  ALL_CIPHER_SUITES,
  cipherSuiteById,
} from '../src/tls/index.js';

describe('Named Groups', () => {
  it('should have correct code points', () => {
    assert.equal(NamedGroup.MLKEM768, 0x0768);
    assert.equal(NamedGroup.MLKEM1024, 0x1024);
    assert.equal(NamedGroup.X25519MLKEM768, 0x6399);
    assert.equal(NamedGroup.SecP256r1MLKEM768, 0x639A);
  });

  it('should resolve from code point', () => {
    assert.equal(namedGroupFromCodePoint(0x6399), NamedGroup.X25519MLKEM768);
    assert.equal(namedGroupFromCodePoint(0xFFFF), undefined);
  });

  it('should provide human-readable names', () => {
    assert.equal(namedGroupName(NamedGroup.X25519MLKEM768), 'X25519MLKEM768');
  });
});

describe('ML-KEM-768 Key Exchange', () => {
  it('should roundtrip correctly', () => {
    const ks = generateKeyShare(NamedGroup.MLKEM768);
    assert.equal(ks.publicKeyShare.length, keyShareSize(NamedGroup.MLKEM768));

    const resp = completeKeyExchange(NamedGroup.MLKEM768, ks.publicKeyShare);
    const ss = recoverSharedSecret(
      NamedGroup.MLKEM768,
      ks.privateKey,
      resp.responseKeyShare,
    );

    assert.deepEqual(resp.sharedSecret, ss);
  });
});

describe('X25519+ML-KEM-768 Hybrid Key Exchange', () => {
  it('should roundtrip correctly', () => {
    const ks = generateKeyShare(NamedGroup.X25519MLKEM768);
    assert.equal(ks.publicKeyShare.length, keyShareSize(NamedGroup.X25519MLKEM768));

    const resp = completeKeyExchange(
      NamedGroup.X25519MLKEM768,
      ks.publicKeyShare,
      ks.classicalEkSize,
    );
    const ss = recoverSharedSecret(
      NamedGroup.X25519MLKEM768,
      ks.privateKey,
      resp.responseKeyShare,
      ks.classicalDkSize,
      resp.classicalCtSize,
    );

    assert.deepEqual(resp.sharedSecret, ss);
  });
});

describe('All groups key share sizes', () => {
  for (const group of ALL_NAMED_GROUPS) {
    it(`${namedGroupName(group)} produces correct key share size`, () => {
      const ks = generateKeyShare(group);
      assert.equal(ks.publicKeyShare.length, keyShareSize(group));
    });
  }
});

describe('Signature Algorithms', () => {
  it('should have correct code points', () => {
    assert.equal(SignatureAlgorithm.MLDSA44, 0x0904);
    assert.equal(SignatureAlgorithm.MLDSA65, 0x0905);
    assert.equal(SignatureAlgorithm.MLDSA87, 0x0906);
    assert.equal(SignatureAlgorithm.MLDSA65_ED25519, 0x0907);
    assert.equal(SignatureAlgorithm.MLDSA87_ED25519, 0x0908);
  });

  it('should resolve from code point', () => {
    assert.equal(signatureAlgorithmFromCodePoint(0x0905), SignatureAlgorithm.MLDSA65);
    assert.equal(signatureAlgorithmFromCodePoint(0xFFFF), undefined);
  });
});

describe('ML-DSA-65 Sign/Verify', () => {
  it('should sign and verify handshake hash', () => {
    const kp = generateSigningKey(SignatureAlgorithm.MLDSA65);
    const hash = new TextEncoder().encode('test handshake transcript hash');
    const sig = signHandshake(SignatureAlgorithm.MLDSA65, kp.sk, hash);
    assert.ok(verifyHandshake(SignatureAlgorithm.MLDSA65, kp.pk, hash, sig));
  });

  it('should fail with wrong key', () => {
    const kp1 = generateSigningKey(SignatureAlgorithm.MLDSA65);
    const kp2 = generateSigningKey(SignatureAlgorithm.MLDSA65);
    const hash = new TextEncoder().encode('test hash');
    const sig = signHandshake(SignatureAlgorithm.MLDSA65, kp1.sk, hash);
    assert.ok(!verifyHandshake(SignatureAlgorithm.MLDSA65, kp2.pk, hash, sig));
  });
});

describe('Composite ML-DSA-65+Ed25519 Sign/Verify', () => {
  it('should sign and verify handshake hash', () => {
    const kp = generateSigningKey(SignatureAlgorithm.MLDSA65_ED25519);
    const hash = new TextEncoder().encode('composite handshake hash');
    // Pass the full key pair object for composite signing (needs JCA key objects)
    const sig = signHandshake(SignatureAlgorithm.MLDSA65_ED25519, kp, hash);
    assert.ok(verifyHandshake(SignatureAlgorithm.MLDSA65_ED25519, kp.pk, hash, sig));
  });
});

describe('Cipher Suites', () => {
  it('should define TLS_AES_128_GCM_SHA256_MLKEM768 correctly', () => {
    const cs = TLS_AES_128_GCM_SHA256_MLKEM768;
    assert.equal(cs.aead, AeadAlgorithm.AES_128_GCM_SHA256);
    assert.equal(cs.keyExchange, NamedGroup.MLKEM768);
    assert.equal(cs.signature, SignatureAlgorithm.MLDSA65);
  });

  it('should look up cipher suites by ID', () => {
    const cs = cipherSuiteById(0x13010768);
    assert.ok(cs);
    assert.equal(cs.name, 'TLS_AES_128_GCM_SHA256_MLKEM768');

    const cs2 = cipherSuiteById(0x13026399);
    assert.ok(cs2);
    assert.equal(cs2.name, 'TLS_AES_256_GCM_SHA384_X25519MLKEM768');

    assert.equal(cipherSuiteById(0xDEADBEEF), undefined);
  });
});

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  keyGen, sign, verify,
  MLDSA65_ED25519, MLDSA65_ECDSA_P256, MLDSA87_ED25519, MLDSA44_ED25519,
} from '../src/composite/index.js';

function testScheme(scheme) {
  describe(scheme.name, () => {
    it('roundtrip: sign then verify', () => {
      const kp = keyGen(scheme);
      const msg = new TextEncoder().encode(`Hello ${scheme.name}`);
      const sig = sign(kp, msg);
      assert.ok(verify(scheme, kp.pk, msg, sig), 'valid sig must verify');
    });

    it('rejects wrong message', () => {
      const kp = keyGen(scheme);
      const msg = new TextEncoder().encode('Original');
      const sig = sign(kp, msg);
      const bad = new TextEncoder().encode('Tampered');
      assert.ok(!verify(scheme, kp.pk, bad, sig), 'wrong msg must fail');
    });

    it('rejects tampered classical sig', () => {
      const kp = keyGen(scheme);
      const msg = new TextEncoder().encode('Tamper classical');
      const sig = sign(kp, msg);
      const tampered = new Uint8Array(sig);
      if (tampered.length > 4) tampered[4] ^= 0xFF;
      assert.ok(!verify(scheme, kp.pk, msg, tampered), 'tampered classical must fail');
    });

    it('rejects tampered PQ sig', () => {
      const kp = keyGen(scheme);
      const msg = new TextEncoder().encode('Tamper PQ');
      const sig = sign(kp, msg);
      const tampered = new Uint8Array(sig);
      tampered[tampered.length - 1] ^= 0xFF;
      assert.ok(!verify(scheme, kp.pk, msg, tampered), 'tampered PQ must fail');
    });
  });
}

describe('Composite Signatures', () => {
  testScheme(MLDSA65_ED25519);
  testScheme(MLDSA65_ECDSA_P256);
  testScheme(MLDSA87_ED25519);
  testScheme(MLDSA44_ED25519);
});

/**
 * PQC Benchmark Suite — JavaScript
 *
 * Benchmarks ML-KEM-768, ML-DSA-65, and SLH-DSA-SHAKE-128f
 * using performance.now() for timing.
 *
 * Run with: node bench/bench.mjs
 */

import { performance } from 'node:perf_hooks';

import { keyGen as kemKeyGen, encaps, decaps, ML_KEM_768 } from '../src/index.js';
import { keyGen as dsaKeyGen, sign as dsaSign, verify as dsaVerify, ML_DSA_65 } from '../src/mldsa/index.js';
import {
  keyGen as slhKeyGen, sign as slhSign, verify as slhVerify,
  SLH_DSA_SHAKE_128f,
} from '../src/slhdsa/index.js';

const ITERATIONS = 100;
const MSG = new TextEncoder().encode('PQC benchmark message for performance testing');

/**
 * Run a function `iterations` times and report the average time in ms.
 */
function bench(name, fn, iterations = ITERATIONS) {
  // Warm-up run
  fn();

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    fn();
  }
  const elapsed = performance.now() - start;
  const avg = elapsed / iterations;
  console.log(`  ${name}: ${avg.toFixed(3)} ms avg (${iterations} iterations, ${elapsed.toFixed(1)} ms total)`);
  return avg;
}

console.log('='.repeat(70));
console.log('PQC Benchmark Suite — JavaScript (Node.js)');
console.log('='.repeat(70));
console.log();

// ---------------------------------------------------------------------------
// ML-KEM-768
// ---------------------------------------------------------------------------
console.log('--- ML-KEM-768 ---');

bench('KeyGen', () => kemKeyGen(ML_KEM_768));

const { ek, dk } = kemKeyGen(ML_KEM_768);
bench('Encaps', () => encaps(ek, ML_KEM_768));

const { c } = encaps(ek, ML_KEM_768);
bench('Decaps', () => decaps(dk, c, ML_KEM_768));

console.log();

// ---------------------------------------------------------------------------
// ML-DSA-65
// ---------------------------------------------------------------------------
console.log('--- ML-DSA-65 ---');

bench('KeyGen', () => dsaKeyGen(ML_DSA_65));

const { pk: dsaPk, sk: dsaSk } = dsaKeyGen(ML_DSA_65);
bench('Sign', () => dsaSign(dsaSk, MSG, ML_DSA_65));

const dsaSig = dsaSign(dsaSk, MSG, ML_DSA_65);
bench('Verify', () => dsaVerify(dsaPk, MSG, dsaSig, ML_DSA_65));

console.log();

// ---------------------------------------------------------------------------
// SLH-DSA-SHAKE-128f
// ---------------------------------------------------------------------------
console.log('--- SLH-DSA-SHAKE-128f ---');

// SLH-DSA is much slower; reduce iteration count
const SLH_ITERS = 5;

bench('KeyGen', () => slhKeyGen(SLH_DSA_SHAKE_128f), SLH_ITERS);

const { sk: slhSk, pk: slhPk } = slhKeyGen(SLH_DSA_SHAKE_128f);
bench('Sign', () => slhSign(MSG, slhSk, SLH_DSA_SHAKE_128f), SLH_ITERS);

const slhSig = slhSign(MSG, slhSk, SLH_DSA_SHAKE_128f);
bench('Verify', () => slhVerify(MSG, slhSig, slhPk, SLH_DSA_SHAKE_128f), SLH_ITERS);

console.log();
console.log('='.repeat(70));
console.log('Benchmark complete.');

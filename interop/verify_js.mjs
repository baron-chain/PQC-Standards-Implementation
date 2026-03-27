#!/usr/bin/env node
/**
 * verify_js.mjs -- Verify ML-DSA-65 interop test vectors using the JS implementation.
 *
 * Usage:
 *     cd PQC-Standards-Implementation
 *     node interop/verify_js.mjs
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Import the JS ML-DSA implementation
import { verify, ML_DSA_65 } from '../js/src/mldsa/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_FILE = join(__dirname, 'mldsa65_vectors.json');

console.log('=== ML-DSA-65 verification (JavaScript) ===');

const raw = readFileSync(VECTORS_FILE, 'utf-8');
const vectors = JSON.parse(raw);

/**
 * Convert a hex string to a Uint8Array.
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

const pk  = hexToBytes(vectors.pk);
const msg = hexToBytes(vectors.msg);
const sig = hexToBytes(vectors.sig);

console.log(`  algorithm : ${vectors.algorithm}`);
console.log(`  pk size   : ${pk.length} bytes`);
console.log(`  msg size  : ${msg.length} bytes`);
console.log(`  sig size  : ${sig.length} bytes`);

const ok = verify(pk, msg, sig, ML_DSA_65);

if (ok) {
  console.log('  result    : PASS');
  process.exit(0);
} else {
  console.log('  result    : FAIL');
  process.exit(1);
}

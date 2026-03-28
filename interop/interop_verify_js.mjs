#!/usr/bin/env node
/**
 * interop_verify_js.mjs — Comprehensive JavaScript cross-language PQC verifier.
 *
 * Reads all JSON vector files from VECTORS_DIR and verifies:
 *   ML-KEM:  decaps(dk, ct) == ss
 *   ML-DSA:  verify(pk, msg, sig) == true
 *   SLH-DSA: slhVerify(msg, sig, pk, params) == true
 *
 * Output lines (parseable by orchestrator):
 *   RESULT:ML-KEM-512:PASS
 *   RESULT:ML-DSA-44:FAIL:verification returned false
 *
 * Usage:
 *   node interop/interop_verify_js.mjs [VECTORS_DIR]
 *   VECTORS_DIR defaults to interop/vectors relative to the repo root.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// Import all algorithm implementations
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const JS_SRC   = join(REPO_ROOT, 'js', 'src');

// ML-KEM
import { decaps as mlkemDecaps } from '../js/src/kem.js';
import {
  ML_KEM_512, ML_KEM_768, ML_KEM_1024,
} from '../js/src/params.js';

// ML-DSA
import { verify as mldsaVerify } from '../js/src/mldsa/dsa.js';
import {
  ML_DSA_44, ML_DSA_65, ML_DSA_87,
} from '../js/src/mldsa/params.js';

// SLH-DSA
import { slhVerify } from '../js/src/slhdsa/slhdsa.js';
import {
  SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_128s,
  SLH_DSA_SHAKE_192f, SLH_DSA_SHAKE_192s,
  SLH_DSA_SHAKE_256f, SLH_DSA_SHAKE_256s,
} from '../js/src/slhdsa/params.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// ML-KEM parameter dispatch
// ---------------------------------------------------------------------------

const MLKEM_PARAMS = {
  'ML-KEM-512':  ML_KEM_512,
  'ML-KEM-768':  ML_KEM_768,
  'ML-KEM-1024': ML_KEM_1024,
};

function verifyMLKEM(alg, vector) {
  const params = MLKEM_PARAMS[alg];
  if (!params) return { pass: false, error: `unknown parameter set: ${alg}` };

  const dk         = hexToBytes(vector.dk);
  const ct         = hexToBytes(vector.ct);
  const ssExpected = hexToBytes(vector.ss);

  let ssGot;
  try {
    ssGot = mlkemDecaps(dk, ct, params);
  } catch (e) {
    return { pass: false, error: `decaps threw: ${e.message}` };
  }

  if (!bytesEqual(ssGot, ssExpected)) {
    return { pass: false, error: 'decapsulated shared secret does not match expected' };
  }
  return { pass: true };
}

// ---------------------------------------------------------------------------
// ML-DSA parameter dispatch
// ---------------------------------------------------------------------------

const MLDSA_PARAMS = {
  'ML-DSA-44': ML_DSA_44,
  'ML-DSA-65': ML_DSA_65,
  'ML-DSA-87': ML_DSA_87,
};

function verifyMLDSA(alg, vector) {
  const params = MLDSA_PARAMS[alg];
  if (!params) return { pass: false, error: `unknown parameter set: ${alg}` };

  const pk  = hexToBytes(vector.pk);
  const msg = hexToBytes(vector.msg);
  const sig = hexToBytes(vector.sig);

  let ok;
  try {
    ok = mldsaVerify(pk, msg, sig, params);
  } catch (e) {
    return { pass: false, error: `verify threw: ${e.message}` };
  }

  if (!ok) return { pass: false, error: 'signature verification returned false' };
  return { pass: true };
}

// ---------------------------------------------------------------------------
// SLH-DSA parameter dispatch
// ---------------------------------------------------------------------------

const SLHDSA_PARAMS = {
  'SLH-DSA-SHAKE-128f': SLH_DSA_SHAKE_128f,
  'SLH-DSA-SHAKE-128s': SLH_DSA_SHAKE_128s,
  'SLH-DSA-SHAKE-192f': SLH_DSA_SHAKE_192f,
  'SLH-DSA-SHAKE-192s': SLH_DSA_SHAKE_192s,
  'SLH-DSA-SHAKE-256f': SLH_DSA_SHAKE_256f,
  'SLH-DSA-SHAKE-256s': SLH_DSA_SHAKE_256s,
};

function verifySLHDSA(alg, vector) {
  const params = SLHDSA_PARAMS[alg];
  if (!params) return { pass: false, error: `unknown parameter set: ${alg}` };

  const pk  = hexToBytes(vector.pk);
  const msg = hexToBytes(vector.msg);
  const sig = hexToBytes(vector.sig);

  let ok;
  try {
    // slhVerify(msg, sig, pk, params) — note argument order matches FIPS 205
    ok = slhVerify(msg, sig, pk, params);
  } catch (e) {
    return { pass: false, error: `verify threw: ${e.message}` };
  }

  if (!ok) return { pass: false, error: 'signature verification returned false' };
  return { pass: true };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const vectorsDir = process.argv[2] ?? join(__dirname, 'vectors');

let entries;
try {
  entries = readdirSync(vectorsDir).filter(f => f.endsWith('.json'));
} catch (e) {
  process.stderr.write(`ERROR: cannot read vectors dir ${vectorsDir}: ${e.message}\n`);
  process.exit(1);
}

let failed = 0;

for (const filename of entries.sort()) {
  const filePath = join(vectorsDir, filename);
  let vector;
  try {
    vector = JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch (e) {
    process.stderr.write(`ERROR: cannot parse ${filename}: ${e.message}\n`);
    failed++;
    continue;
  }

  const alg = vector.algorithm;
  let result;

  if (alg.startsWith('ML-KEM')) {
    result = verifyMLKEM(alg, vector);
  } else if (alg.startsWith('ML-DSA')) {
    result = verifyMLDSA(alg, vector);
  } else if (alg.startsWith('SLH-DSA')) {
    result = verifySLHDSA(alg, vector);
  } else {
    result = { pass: false, error: `unknown algorithm family: ${alg}` };
  }

  if (result.pass) {
    console.log(`RESULT:${alg}:PASS`);
  } else {
    console.log(`RESULT:${alg}:FAIL:${result.error}`);
    failed++;
  }
}

process.exit(failed > 0 ? 1 : 0);

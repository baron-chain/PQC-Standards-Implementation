<?php
/**
 * interop_verify_php.php — PHP cross-language PQC verifier.
 *
 * Reads all JSON vector files from VECTORS_DIR and verifies:
 *   ML-KEM:  decaps(dk, ct) == ss
 *   ML-DSA:  verify(pk, msg, sig) == true
 *   SLH-DSA: verify(pk, msg, sig) == true
 *
 * Output lines (parseable by orchestrator):
 *   RESULT:ML-KEM-512:PASS
 *   RESULT:ML-DSA-44:FAIL:verification returned false
 *
 * Usage:
 *   php interop/interop_verify_php.php [VECTORS_DIR]
 *   VECTORS_DIR defaults to interop/vectors relative to the repo root.
 */

declare(strict_types=1);

// Locate the PHP project autoloader
$repoRoot = dirname(__DIR__);
$autoload = $repoRoot . '/php/vendor/autoload.php';
if (!file_exists($autoload)) {
    fwrite(STDERR, "ERROR: PHP autoloader not found at $autoload\n");
    fwrite(STDERR, "Run: cd php && composer install\n");
    exit(1);
}
require_once $autoload;

use PQC\MlKem\MlKem;
use PQC\MlDsa\MlDsa;
use PQC\SlhDsa\SlhDsa;

$vectorsDir = $argv[1] ?? ($repoRoot . '/interop/vectors');

if (!is_dir($vectorsDir)) {
    fwrite(STDERR, "ERROR: Vectors directory not found: $vectorsDir\n");
    exit(1);
}

// -----------------------------------------------------------------------
// Helper
// -----------------------------------------------------------------------
function hexToBytes(string $hex): string
{
    return hex2bin($hex);
}

function bytesEqual(string $a, string $b): bool
{
    return hash_equals($a, $b);
}

// -----------------------------------------------------------------------
// ML-KEM parameter dispatch
// -----------------------------------------------------------------------
$MLKEM_LEVELS = [
    'ML-KEM-512'  => 512,
    'ML-KEM-768'  => 768,
    'ML-KEM-1024' => 1024,
];

// -----------------------------------------------------------------------
// ML-DSA parameter dispatch
// -----------------------------------------------------------------------
$MLDSA_LEVELS = [
    'ML-DSA-44' => 44,
    'ML-DSA-65' => 65,
    'ML-DSA-87' => 87,
];

// -----------------------------------------------------------------------
// SLH-DSA parameter dispatch (algorithm name → variant string)
// -----------------------------------------------------------------------
$SLHDSA_VARIANTS = [
    'SLH-DSA-SHAKE-128f' => 'shake-128f',
    'SLH-DSA-SHAKE-128s' => 'shake-128s',
    'SLH-DSA-SHAKE-192f' => 'shake-192f',
    'SLH-DSA-SHAKE-192s' => 'shake-192s',
    'SLH-DSA-SHAKE-256f' => 'shake-256f',
    'SLH-DSA-SHAKE-256s' => 'shake-256s',
];

// -----------------------------------------------------------------------
// Process all vector files
// -----------------------------------------------------------------------
$jsonFiles = glob($vectorsDir . '/*.json');
if (empty($jsonFiles)) {
    fwrite(STDERR, "ERROR: No JSON files found in $vectorsDir\n");
    exit(1);
}

foreach ($jsonFiles as $jsonFile) {
    $raw = file_get_contents($jsonFile);
    if ($raw === false) {
        continue;
    }
    $vec = json_decode($raw, true);
    if (!is_array($vec) || !isset($vec['algorithm'])) {
        continue;
    }

    $alg = $vec['algorithm'];

    try {
        // -----------------------------------------------------------------
        // ML-KEM: verify decaps(dk, ct) == ss
        // -----------------------------------------------------------------
        if (isset($MLKEM_LEVELS[$alg])) {
            $level = $MLKEM_LEVELS[$alg];
            $dk = hexToBytes($vec['dk']);
            $ct = hexToBytes($vec['ct']);
            $expectedSs = hexToBytes($vec['ss']);

            $ss = MlKem::decaps($ct, $dk, $level);

            if (!bytesEqual($ss, $expectedSs)) {
                echo "RESULT:$alg:FAIL:shared secret mismatch\n";
            } else {
                echo "RESULT:$alg:PASS\n";
            }

        // -----------------------------------------------------------------
        // ML-DSA: verify(pk, msg, sig) == true
        // -----------------------------------------------------------------
        } elseif (isset($MLDSA_LEVELS[$alg])) {
            $level = $MLDSA_LEVELS[$alg];
            $pk  = hexToBytes($vec['pk']);
            $msg = hexToBytes($vec['msg']);
            $sig = hexToBytes($vec['sig']);

            $ok = MlDsa::verify($pk, $msg, $sig, $level);

            if (!$ok) {
                echo "RESULT:$alg:FAIL:verification returned false\n";
            } else {
                echo "RESULT:$alg:PASS\n";
            }

        // -----------------------------------------------------------------
        // SLH-DSA: verify(pk, msg, sig) == true
        // -----------------------------------------------------------------
        } elseif (isset($SLHDSA_VARIANTS[$alg])) {
            $variant = $SLHDSA_VARIANTS[$alg];
            $pk  = hexToBytes($vec['pk']);
            $msg = hexToBytes($vec['msg']);
            $sig = hexToBytes($vec['sig']);

            $ok = SlhDsa::verify($pk, $msg, $sig, $variant);

            if (!$ok) {
                echo "RESULT:$alg:FAIL:verification returned false\n";
            } else {
                echo "RESULT:$alg:PASS\n";
            }

        } else {
            // Unknown algorithm — skip silently
        }
    } catch (\Throwable $e) {
        echo "RESULT:$alg:FAIL:" . str_replace(["\n", ":"], [" ", ";"], $e->getMessage()) . "\n";
    }
}

<?php

declare(strict_types=1);

namespace PQC\SlhDsa;

/**
 * SLH-DSA parameter sets (FIPS 205).
 * Using SHAKE-based instantiation.
 */
final class SlhParams
{
    /**
     * Get parameters for the given variant.
     *
     * @param string $variant e.g., 'shake-128f', 'shake-128s', 'shake-192f', 'shake-256f'
     * @return array
     */
    public static function get(string $variant): array
    {
        return match ($variant) {
            'shake-128f' => [
                'n' => 16,
                'w' => 16,
                'h' => 66,      // total tree height
                'hPrime' => 6,  // XMSS tree height (h' in spec, called d' sometimes)
                'd' => 11,       // hypertree layers (note: h = hPrime * d + fors_height concept is diff)
                // Actually for SLH-DSA: h = d * hPrime
                // Let me use the FIPS 205 exact params:
                'full_height' => 66,
                'tree_height' => 6, // h'
                'layers' => 11,     // d
                'k' => 33,          // FORS trees
                'a' => 6,           // FORS height (log leaves)
                'lg_w' => 4,
                'len1' => 32,       // ceil(8n / lg(w))
                'len2' => 3,        // floor(log_w(len1 * (w-1))) + 1
                'len' => 35,        // len1 + len2
                'hashName' => 'shake-128',
                'mdLen' => 30,      // ceil((k*a + 7) / 8) for message digest
                'treeIdxLen' => 8,
                'leafIdxLen' => 1,
            ],
            'shake-128s' => [
                'n' => 16,
                'w' => 16,
                'full_height' => 63,
                'tree_height' => 9,
                'layers' => 7,
                'k' => 14,
                'a' => 12,
                'lg_w' => 4,
                'len1' => 32,
                'len2' => 3,
                'len' => 35,
                'hashName' => 'shake-128',
                'mdLen' => 27,
                'treeIdxLen' => 7,
                'leafIdxLen' => 2,
            ],
            'shake-256f' => [
                'n' => 32,
                'w' => 16,
                'full_height' => 68,
                'tree_height' => 17,
                'layers' => 4,
                'k' => 35,
                'a' => 4,
                'lg_w' => 4,
                'len1' => 64,
                'len2' => 3,
                'len' => 67,
                'hashName' => 'shake-256',
                'mdLen' => 40,
                'treeIdxLen' => 4,
                'leafIdxLen' => 3,
            ],
            default => throw new \InvalidArgumentException("Unknown SLH-DSA variant: $variant"),
        };
    }

    /**
     * Signature size in bytes.
     */
    public static function sigSize(string $variant): int
    {
        $p = self::get($variant);
        $n = $p['n'];
        // sig = R (n) + FORS sig (k * (a+1) * n) + HT sig (d * (h' + len) * n)
        $forsSigSize = $p['k'] * ($p['a'] + 1) * $n;
        $htSigSize = $p['layers'] * ($p['tree_height'] + $p['len']) * $n;
        return $n + $forsSigSize + $htSigSize;
    }

    /**
     * Public key size: SK.seed(n) + PK.root(n).
     */
    public static function pkSize(string $variant): int
    {
        $p = self::get($variant);
        return 2 * $p['n'];
    }

    /**
     * Secret key size: SK.seed(n) + SK.prf(n) + PK.seed(n) + PK.root(n).
     */
    public static function skSize(string $variant): int
    {
        $p = self::get($variant);
        return 4 * $p['n'];
    }
}

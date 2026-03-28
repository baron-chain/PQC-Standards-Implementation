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
     * @param string $variant e.g., 'shake-128f', 'shake-128s', 'shake-192f', etc.
     * @return array
     */
    public static function get(string $variant): array
    {
        return match ($variant) {
            'shake-128f' => [
                'n'           => 16,
                'w'           => 16,
                'full_height' => 66,
                'tree_height' => 3,   // h' = h/d = 66/22 = 3
                'layers'      => 22,  // d
                'k'           => 33,  // FORS trees
                'a'           => 6,   // FORS height (log2 leaves per tree)
                'lg_w'        => 4,
                'len1'        => 32,
                'len2'        => 3,
                'len'         => 35,
                'hashName'    => 'shake-128',
                'mdLen'       => 34,  // ceil(k*a/8) + treeIdxLen + leafIdxLen = 25+8+1
                'treeIdxLen'  => 8,   // ceil((h-h')/8) = ceil(63/8) = 8
                'leafIdxLen'  => 1,   // ceil(h'/8) = ceil(3/8) = 1
            ],
            'shake-128s' => [
                'n'           => 16,
                'w'           => 16,
                'full_height' => 63,
                'tree_height' => 9,
                'layers'      => 7,
                'k'           => 14,
                'a'           => 12,
                'lg_w'        => 4,
                'len1'        => 32,
                'len2'        => 3,
                'len'         => 35,
                'hashName'    => 'shake-128',
                'mdLen'       => 30,  // ceil(14*12/8) + 7 + 2 = 21+7+2
                'treeIdxLen'  => 7,   // ceil(54/8) = 7
                'leafIdxLen'  => 2,   // ceil(9/8) = 2
            ],
            'shake-192f' => [
                'n'           => 24,
                'w'           => 16,
                'full_height' => 66,
                'tree_height' => 3,
                'layers'      => 22,
                'k'           => 33,
                'a'           => 8,
                'lg_w'        => 4,
                'len1'        => 48,
                'len2'        => 3,
                'len'         => 51,
                'hashName'    => 'shake-256',
                'mdLen'       => 42,  // ceil(33*8/8) + 8 + 1 = 33+8+1
                'treeIdxLen'  => 8,   // ceil(63/8) = 8
                'leafIdxLen'  => 1,   // ceil(3/8) = 1
            ],
            'shake-192s' => [
                'n'           => 24,
                'w'           => 16,
                'full_height' => 63,
                'tree_height' => 9,
                'layers'      => 7,
                'k'           => 17,
                'a'           => 14,
                'lg_w'        => 4,
                'len1'        => 48,
                'len2'        => 3,
                'len'         => 51,
                'hashName'    => 'shake-256',
                'mdLen'       => 39,  // ceil(17*14/8) + 7 + 2 = 30+7+2
                'treeIdxLen'  => 7,   // ceil(54/8) = 7
                'leafIdxLen'  => 2,   // ceil(9/8) = 2
            ],
            'shake-256f' => [
                'n'           => 32,
                'w'           => 16,
                'full_height' => 68,
                'tree_height' => 4,   // h' = h/d = 68/17 = 4
                'layers'      => 17,  // d
                'k'           => 35,
                'a'           => 9,
                'lg_w'        => 4,
                'len1'        => 64,
                'len2'        => 3,
                'len'         => 67,
                'hashName'    => 'shake-256',
                'mdLen'       => 49,  // ceil(35*9/8) + 8 + 1 = 40+8+1
                'treeIdxLen'  => 8,   // ceil(64/8) = 8
                'leafIdxLen'  => 1,   // ceil(4/8) = 1
            ],
            'shake-256s' => [
                'n'           => 32,
                'w'           => 16,
                'full_height' => 64,
                'tree_height' => 8,
                'layers'      => 8,
                'k'           => 22,
                'a'           => 14,
                'lg_w'        => 4,
                'len1'        => 64,
                'len2'        => 3,
                'len'         => 67,
                'hashName'    => 'shake-256',
                'mdLen'       => 47,  // ceil(22*14/8) + 7 + 1 = 39+7+1
                'treeIdxLen'  => 7,   // ceil(56/8) = 7
                'leafIdxLen'  => 1,   // ceil(8/8) = 1
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
     * Public key size: PK.seed(n) + PK.root(n).
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

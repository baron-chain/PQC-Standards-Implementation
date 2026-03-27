<?php

declare(strict_types=1);

namespace PQC\MlDsa;

/**
 * ML-DSA parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87.
 */
final class DsaParams
{
    public const N = 256;
    public const Q = 8380417;
    public const D = 13;  // Dropped bits from t

    /**
     * Get parameters for given security level.
     *
     * @param int $level 44, 65, or 87
     */
    public static function get(int $level): array
    {
        return match ($level) {
            44 => [
                'k' => 4, 'l' => 4,
                'eta' => 2, 'tau' => 39,
                'beta' => 78,  // tau * eta
                'gamma1' => (1 << 17), // 2^17
                'gamma2' => (self::Q - 1) / 88,
                'omega' => 80,
                'lambda' => 128,  // collision strength in bits
                'ctilde_len' => 32,
            ],
            65 => [
                'k' => 6, 'l' => 5,
                'eta' => 4, 'tau' => 49,
                'beta' => 196,
                'gamma1' => (1 << 19),
                'gamma2' => (self::Q - 1) / 32,
                'omega' => 55,
                'lambda' => 192,
                'ctilde_len' => 48,
            ],
            87 => [
                'k' => 8, 'l' => 7,
                'eta' => 2, 'tau' => 60,
                'beta' => 120,
                'gamma1' => (1 << 19),
                'gamma2' => (self::Q - 1) / 32,
                'omega' => 75,
                'lambda' => 256,
                'ctilde_len' => 64,
            ],
            default => throw new \InvalidArgumentException("Invalid ML-DSA level: $level"),
        };
    }

    /**
     * Signature size in bytes.
     */
    public static function sigSize(int $level): int
    {
        $p = self::get($level);
        $k = $p['k'];
        $l = $p['l'];
        $gamma1 = $p['gamma1'];

        $gamma1Bits = (int)log($gamma1, 2) + 1; // 18 or 20
        $zSize = $l * 32 * $gamma1Bits; // l * 256 * gamma1Bits / 8
        $hSize = $p['omega'] + $k;

        return $p['ctilde_len'] + intdiv($l * 256 * $gamma1Bits, 8) + $hSize;
    }
}

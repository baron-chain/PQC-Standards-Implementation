<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * Field arithmetic modulo q=3329 for ML-KEM.
 */
final class Field
{
    public const Q = 3329;
    public const Q_INV = 62209; // q^{-1} mod 2^16

    /**
     * Reduce mod q into [0, q).
     */
    public static function mod(int $a): int
    {
        $r = $a % self::Q;
        return $r < 0 ? $r + self::Q : $r;
    }

    /**
     * Addition mod q.
     */
    public static function add(int $a, int $b): int
    {
        return self::mod($a + $b);
    }

    /**
     * Subtraction mod q.
     */
    public static function sub(int $a, int $b): int
    {
        return self::mod($a - $b);
    }

    /**
     * Multiplication mod q.
     */
    public static function mul(int $a, int $b): int
    {
        return self::mod($a * $b);
    }

    /**
     * Montgomery reduction: given a < q * 2^16, compute a * 2^{-16} mod q.
     */
    public static function montgomeryReduce(int $a): int
    {
        // Not strictly needed for our implementation, but available.
        $t = (($a & 0xFFFF) * self::Q_INV) & 0xFFFF;
        $r = ($a - $t * self::Q) >> 16;
        return $r < 0 ? $r + self::Q : $r;
    }

    /**
     * Barrett reduction for values < 2*q.
     */
    public static function barrettReduce(int $a): int
    {
        $v = (int)((1 << 26) / self::Q + 1);
        $t = ($v * $a) >> 26;
        $t = $a - $t * self::Q;
        if ($t >= self::Q) {
            $t -= self::Q;
        }
        return $t;
    }

    /**
     * Conditional subtraction of q.
     */
    public static function csubq(int $a): int
    {
        $a -= self::Q;
        return $a < 0 ? $a + self::Q : $a;
    }

    /**
     * Power mod q using repeated squaring.
     */
    public static function pow(int $base, int $exp): int
    {
        $result = 1;
        $base = self::mod($base);
        while ($exp > 0) {
            if ($exp & 1) {
                $result = self::mul($result, $base);
            }
            $exp >>= 1;
            $base = self::mul($base, $base);
        }
        return $result;
    }

    /**
     * Inverse mod q using Fermat's little theorem: a^{-1} = a^{q-2} mod q.
     */
    public static function inv(int $a): int
    {
        return self::pow($a, self::Q - 2);
    }
}

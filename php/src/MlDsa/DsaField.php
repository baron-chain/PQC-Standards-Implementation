<?php

declare(strict_types=1);

namespace PQC\MlDsa;

/**
 * Field arithmetic modulo q=8380417 for ML-DSA.
 */
final class DsaField
{
    public const Q = 8380417;
    public const Q_HALF = 4190208; // (Q-1)/2

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
     * Power mod q.
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
     * Inverse mod q.
     */
    public static function inv(int $a): int
    {
        return self::pow($a, self::Q - 2);
    }

    /**
     * Centered representative: map [0, q) to [-(q-1)/2, (q-1)/2].
     */
    public static function centered(int $a): int
    {
        $a = self::mod($a);
        if ($a > self::Q_HALF) {
            return $a - self::Q;
        }
        return $a;
    }

    /**
     * Infinity norm of a polynomial.
     */
    public static function polyNorm(array $poly): int
    {
        $max = 0;
        foreach ($poly as $c) {
            $v = abs(self::centered($c));
            if ($v > $max) {
                $max = $v;
            }
        }
        return $max;
    }

    /**
     * Infinity norm of a vector of polynomials.
     */
    public static function vecNorm(array $vec): int
    {
        $max = 0;
        foreach ($vec as $poly) {
            $n = self::polyNorm($poly);
            if ($n > $max) {
                $max = $n;
            }
        }
        return $max;
    }
}

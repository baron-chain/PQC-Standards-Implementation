<?php

declare(strict_types=1);

namespace PQC\MlDsa;

/**
 * Decompose, Power2Round, MakeHint, UseHint for ML-DSA.
 */
final class Decompose
{
    /**
     * Power2Round: decompose r into (r1, r0) where r = r1*2^d + r0.
     * FIPS 204 Algorithm 30.
     *
     * @return array{int, int} [r1, r0]
     */
    public static function power2Round(int $r): array
    {
        $r = DsaField::mod($r);
        $d = DsaParams::D;
        $r0 = $r % (1 << $d);
        if ($r0 > (1 << ($d - 1))) {
            $r0 -= (1 << $d);
        }
        $r1 = ($r - $r0) >> $d;
        return [$r1, DsaField::mod($r0)];
    }

    /**
     * Decompose: high bits and low bits relative to gamma2.
     * FIPS 204 Algorithm 31.
     *
     * @return array{int, int} [r1, r0]
     */
    public static function decompose(int $r, int $gamma2): array
    {
        $r = DsaField::mod($r);
        $r0 = $r % (2 * $gamma2);
        if ($r0 > $gamma2) {
            $r0 -= 2 * $gamma2;
        }

        if ($r - $r0 === DsaField::Q - 1) {
            $r1 = 0;
            $r0 = $r0 - 1;
        } else {
            $r1 = intdiv($r - $r0, 2 * $gamma2);
        }

        return [$r1, $r0];
    }

    /**
     * HighBits.
     */
    public static function highBits(int $r, int $gamma2): int
    {
        return self::decompose($r, $gamma2)[0];
    }

    /**
     * LowBits.
     */
    public static function lowBits(int $r, int $gamma2): int
    {
        return self::decompose($r, $gamma2)[1];
    }

    /**
     * MakeHint: compute hint bit.
     * FIPS 204 Algorithm 32.
     */
    public static function makeHint(int $z, int $r, int $gamma2): int
    {
        $r1 = self::highBits($r, $gamma2);
        $v1 = self::highBits(DsaField::add($r, $z), $gamma2);
        return ($r1 !== $v1) ? 1 : 0;
    }

    /**
     * UseHint: apply hint to recover high bits.
     * FIPS 204 Algorithm 33.
     */
    public static function useHint(int $hint, int $r, int $gamma2): int
    {
        $m = intdiv(DsaField::Q - 1, 2 * $gamma2);
        [$r1, $r0] = self::decompose($r, $gamma2);

        if ($hint === 0) {
            return $r1;
        }

        if ($r0 > 0) {
            return ($r1 + 1) % $m;
        }

        return ($r1 - 1 + $m) % $m;
    }

    /**
     * Power2Round for entire polynomial.
     */
    public static function power2RoundPoly(array $poly): array
    {
        $hi = [];
        $lo = [];
        for ($i = 0; $i < 256; $i++) {
            [$hi[$i], $lo[$i]] = self::power2Round($poly[$i]);
        }
        return [$hi, $lo];
    }

    /**
     * Power2Round for vector of polynomials.
     */
    public static function power2RoundVec(array $vec): array
    {
        $hiVec = [];
        $loVec = [];
        foreach ($vec as $idx => $poly) {
            [$hiVec[$idx], $loVec[$idx]] = self::power2RoundPoly($poly);
        }
        return [$hiVec, $loVec];
    }

    /**
     * Decompose for entire polynomial.
     */
    public static function decomposePoly(array $poly, int $gamma2): array
    {
        $hi = [];
        $lo = [];
        for ($i = 0; $i < 256; $i++) {
            [$hi[$i], $lo[$i]] = self::decompose($poly[$i], $gamma2);
        }
        return [$hi, $lo];
    }

    /**
     * HighBits for vector.
     */
    public static function highBitsVec(array $vec, int $gamma2): array
    {
        $result = [];
        foreach ($vec as $idx => $poly) {
            $result[$idx] = [];
            for ($i = 0; $i < 256; $i++) {
                $result[$idx][$i] = self::highBits($poly[$i], $gamma2);
            }
        }
        return $result;
    }

    /**
     * LowBits for vector.
     */
    public static function lowBitsVec(array $vec, int $gamma2): array
    {
        $result = [];
        foreach ($vec as $idx => $poly) {
            $result[$idx] = [];
            for ($i = 0; $i < 256; $i++) {
                $result[$idx][$i] = self::lowBits($poly[$i], $gamma2);
            }
        }
        return $result;
    }

    /**
     * MakeHint for vectors.
     */
    public static function makeHintVec(array $z, array $r, int $gamma2, int $k): array
    {
        $h = [];
        $numOnes = 0;
        for ($i = 0; $i < $k; $i++) {
            $h[$i] = [];
            for ($j = 0; $j < 256; $j++) {
                $h[$i][$j] = self::makeHint($z[$i][$j], $r[$i][$j], $gamma2);
                $numOnes += $h[$i][$j];
            }
        }
        return [$h, $numOnes];
    }

    /**
     * UseHint for vector.
     */
    public static function useHintVec(array $hint, array $r, int $gamma2, int $k): array
    {
        $result = [];
        for ($i = 0; $i < $k; $i++) {
            $result[$i] = [];
            for ($j = 0; $j < 256; $j++) {
                $result[$i][$j] = self::useHint($hint[$i][$j], $r[$i][$j], $gamma2);
            }
        }
        return $result;
    }
}

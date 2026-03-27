<?php

declare(strict_types=1);

namespace PQC\MlDsa;

use PQC\MlKem\HashFuncs;

/**
 * Hash functions for ML-DSA.
 */
final class DsaHash
{
    /**
     * H (SHAKE-256 with variable output).
     */
    public static function H(string $input, int $outLen): string
    {
        return HashFuncs::shake256($input, $outLen);
    }

    /**
     * SHAKE-128 XOF.
     */
    public static function shake128(string $input, int $outLen): string
    {
        return HashFuncs::shake128($input, $outLen);
    }

    /**
     * SHAKE-256 XOF.
     */
    public static function shake256(string $input, int $outLen): string
    {
        return HashFuncs::shake256($input, $outLen);
    }

    /**
     * ExpandA: sample matrix A from rho using SHAKE-128.
     * FIPS 204 Algorithm 26.
     */
    public static function expandA(string $rho, int $k, int $l): array
    {
        $A = [];
        for ($r = 0; $r < $k; $r++) {
            for ($s = 0; $s < $l; $s++) {
                $A[$r][$s] = self::rejNttPoly($rho . chr($s) . chr($r));
            }
        }
        return $A;
    }

    /**
     * RejNTTPoly: rejection sampling to produce NTT-domain polynomial.
     * FIPS 204 Algorithm 24.
     */
    public static function rejNttPoly(string $seed): array
    {
        $stream = self::shake128($seed, 256 * 4);
        $coeffs = [];
        $pos = 0;

        while (count($coeffs) < 256) {
            if ($pos + 3 > strlen($stream)) {
                $stream .= self::shake128($seed . pack('V', $pos), 256 * 4);
            }
            $b0 = ord($stream[$pos++]);
            $b1 = ord($stream[$pos++]);
            $b2 = ord($stream[$pos++]);

            $val = $b0 | ($b1 << 8) | ($b2 << 16);
            $val &= 0x7FFFFF; // 23 bits

            if ($val < DsaField::Q) {
                $coeffs[] = $val;
            }
        }

        return array_slice($coeffs, 0, 256);
    }

    /**
     * ExpandS: sample secret vectors s1, s2 from rhoPrime.
     * FIPS 204 Algorithm 27.
     */
    public static function expandS(string $rhoPrime, int $eta, int $k, int $l): array
    {
        $s1 = [];
        for ($r = 0; $r < $l; $r++) {
            $s1[$r] = self::rejBoundedPoly($rhoPrime . pack('v', $r), $eta);
        }

        $s2 = [];
        for ($r = 0; $r < $k; $r++) {
            $s2[$r] = self::rejBoundedPoly($rhoPrime . pack('v', $l + $r), $eta);
        }

        return [$s1, $s2];
    }

    /**
     * RejBoundedPoly: sample polynomial with coefficients in [-eta, eta].
     * FIPS 204 Algorithm 25.
     */
    public static function rejBoundedPoly(string $seed, int $eta): array
    {
        $stream = self::shake256($seed, 256 * 2);
        $coeffs = [];
        $pos = 0;

        while (count($coeffs) < 256) {
            if ($pos >= strlen($stream)) {
                $stream .= self::shake256($seed . pack('V', $pos), 256 * 2);
            }
            $byte = ord($stream[$pos++]);

            $z0 = $byte & 0x0F;
            $z1 = $byte >> 4;

            if ($eta === 2) {
                if ($z0 < 15) {
                    $val = $z0 - (int)(($z0 * 205) >> 10) * 5;
                    $coeffs[] = DsaField::mod($eta - $val);
                }
                if (count($coeffs) < 256 && $z1 < 15) {
                    $val = $z1 - (int)(($z1 * 205) >> 10) * 5;
                    $coeffs[] = DsaField::mod($eta - $val);
                }
            } else { // eta = 4
                if ($z0 < 9) {
                    $coeffs[] = DsaField::mod($eta - $z0);
                }
                if (count($coeffs) < 256 && $z1 < 9) {
                    $coeffs[] = DsaField::mod($eta - $z1);
                }
            }
        }

        return array_slice($coeffs, 0, 256);
    }

    /**
     * ExpandMask: sample mask vector y from rhoPrime and kappa.
     * FIPS 204 Algorithm 28.
     */
    public static function expandMask(string $rhoPrime, int $kappa, int $l, int $gamma1): array
    {
        $y = [];
        $gamma1Bits = ($gamma1 === (1 << 17)) ? 18 : 20;

        for ($r = 0; $r < $l; $r++) {
            $stream = self::shake256(
                $rhoPrime . pack('v', $kappa + $r),
                32 * $gamma1Bits
            );
            $y[$r] = self::bitUnpackGamma1($stream, $gamma1, $gamma1Bits);
        }

        return $y;
    }

    /**
     * Unpack gamma1-bounded coefficients from byte stream.
     */
    private static function bitUnpackGamma1(string $stream, int $gamma1, int $bits): array
    {
        $coeffs = [];
        if ($bits === 18) {
            // 9 bytes -> 4 coefficients
            for ($i = 0; $i < 64; $i++) {
                $offset = $i * 9;
                $b = [];
                for ($j = 0; $j < 9; $j++) {
                    $b[$j] = ord($stream[$offset + $j]);
                }

                $val0 = $b[0] | ($b[1] << 8) | (($b[2] & 0x03) << 16);
                $val1 = (($b[2] >> 2) | ($b[3] << 6) | (($b[4] & 0x0F) << 14));
                $val2 = (($b[4] >> 4) | ($b[5] << 4) | (($b[6] & 0x3F) << 12));
                $val3 = (($b[6] >> 6) | ($b[7] << 2) | ($b[8] << 10));

                $val0 &= 0x3FFFF;
                $val1 &= 0x3FFFF;
                $val2 &= 0x3FFFF;
                $val3 &= 0x3FFFF;

                $coeffs[] = DsaField::mod($gamma1 - $val0);
                $coeffs[] = DsaField::mod($gamma1 - $val1);
                $coeffs[] = DsaField::mod($gamma1 - $val2);
                $coeffs[] = DsaField::mod($gamma1 - $val3);
            }
        } else { // 20 bits
            // 5 bytes -> 2 coefficients
            for ($i = 0; $i < 128; $i++) {
                $offset = $i * 5;
                $b0 = ord($stream[$offset]);
                $b1 = ord($stream[$offset + 1]);
                $b2 = ord($stream[$offset + 2]);
                $b3 = ord($stream[$offset + 3]);
                $b4 = ord($stream[$offset + 4]);

                $val0 = $b0 | ($b1 << 8) | (($b2 & 0x0F) << 16);
                $val1 = ($b2 >> 4) | ($b3 << 4) | ($b4 << 12);

                $val0 &= 0xFFFFF;
                $val1 &= 0xFFFFF;

                $coeffs[] = DsaField::mod($gamma1 - $val0);
                $coeffs[] = DsaField::mod($gamma1 - $val1);
            }
        }

        return array_slice($coeffs, 0, 256);
    }

    /**
     * SampleInBall: generate challenge polynomial c with tau +/-1 coefficients.
     * FIPS 204 Algorithm 29.
     */
    public static function sampleInBall(string $seed, int $tau): array
    {
        $stream = self::shake256($seed, 8 + 256);
        $c = array_fill(0, 256, 0);

        // Extract sign bits from first 8 bytes
        $signs = 0;
        for ($i = 7; $i >= 0; $i--) {
            $signs = ($signs << 8) | ord($stream[$i]);
        }

        $pos = 8;
        for ($i = 256 - $tau; $i < 256; $i++) {
            // Get j from stream
            while (true) {
                if ($pos >= strlen($stream)) {
                    $stream .= self::shake256($seed . pack('V', $pos), 256);
                }
                $j = ord($stream[$pos++]);
                if ($j <= $i) break;
            }

            $c[$i] = $c[$j];
            $c[$j] = (($signs & 1) === 0) ? 1 : DsaField::mod(-1);
            $signs >>= 1;
        }

        return $c;
    }
}

<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * Sampling functions for ML-KEM.
 */
final class Sampling
{
    /**
     * SampleNTT: sample a polynomial in NTT domain from XOF stream.
     * FIPS 203 Algorithm 6.
     *
     * @param string $rho Public seed (32 bytes)
     * @param int $i Row index
     * @param int $j Column index
     * @return array Polynomial in NTT domain (256 coefficients)
     */
    public static function sampleNtt(string $rho, int $i, int $j): array
    {
        // Generate enough XOF output
        $stream = HashFuncs::XOF($rho, $i, $j, 256 * 3);
        $coeffs = [];
        $pos = 0;

        while (count($coeffs) < 256) {
            if ($pos + 3 > strlen($stream)) {
                // Need more bytes
                $stream .= HashFuncs::XOF($rho . chr($j) . chr($i) . pack('V', $pos), 0, 0, 256 * 3);
            }
            $b0 = ord($stream[$pos++]);
            $b1 = ord($stream[$pos++]);
            $b2 = ord($stream[$pos++]);

            $d1 = $b0 | (($b1 & 0x0F) << 8);
            $d2 = ($b1 >> 4) | ($b2 << 4);

            if ($d1 < Field::Q) {
                $coeffs[] = $d1;
            }
            if (count($coeffs) < 256 && $d2 < Field::Q) {
                $coeffs[] = $d2;
            }
        }

        return array_slice($coeffs, 0, 256);
    }

    /**
     * SamplePolyCBD: sample polynomial from CBD (centered binomial distribution).
     * FIPS 203 Algorithm 7.
     *
     * @param string $bytes PRF output bytes
     * @param int $eta The eta parameter (2 or 3)
     * @return array Polynomial (256 coefficients)
     */
    public static function samplePolyCBD(string $bytes, int $eta): array
    {
        $bits = [];
        for ($i = 0; $i < strlen($bytes); $i++) {
            $byte = ord($bytes[$i]);
            for ($j = 0; $j < 8; $j++) {
                $bits[] = ($byte >> $j) & 1;
            }
        }

        $f = [];
        for ($i = 0; $i < 256; $i++) {
            $a = 0;
            $b = 0;
            for ($j = 0; $j < $eta; $j++) {
                $a += $bits[2 * $i * $eta + $j];
                $b += $bits[2 * $i * $eta + $eta + $j];
            }
            $f[$i] = Field::mod($a - $b);
        }

        return $f;
    }

    /**
     * Sample noise vector (k polynomials using CBD).
     *
     * @param string $sigma PRF key
     * @param int $eta CBD parameter
     * @param int $k Number of polynomials
     * @param int $offset Starting counter value
     * @return array Array of k polynomials
     */
    public static function sampleNoiseVec(string $sigma, int $eta, int $k, int $offset): array
    {
        $vec = [];
        $prfLen = 64 * $eta;
        for ($i = 0; $i < $k; $i++) {
            $prfOutput = HashFuncs::PRF($sigma, $offset + $i, $prfLen);
            $vec[$i] = self::samplePolyCBD($prfOutput, $eta);
        }
        return $vec;
    }

    /**
     * Sample noise polynomial using CBD.
     */
    public static function sampleNoisePoly(string $sigma, int $eta, int $counter): array
    {
        $prfLen = 64 * $eta;
        $prfOutput = HashFuncs::PRF($sigma, $counter, $prfLen);
        return self::samplePolyCBD($prfOutput, $eta);
    }
}

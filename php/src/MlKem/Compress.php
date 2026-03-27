<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * Compress/Decompress functions for ML-KEM.
 */
final class Compress
{
    /**
     * Compress: round(2^d / q * x) mod 2^d.
     * FIPS 203 Section 4.2.1.
     */
    public static function compress(int $x, int $d): int
    {
        // Compress_d(x) = Round((2^d / q) * x) mod 2^d
        $shifted = ($x << $d) + (Field::Q >> 1); // Add q/2 for rounding
        $result = intdiv($shifted, Field::Q);
        return $result & ((1 << $d) - 1);
    }

    /**
     * Decompress: round(q / 2^d * y).
     * FIPS 203 Section 4.2.1.
     */
    public static function decompress(int $y, int $d): int
    {
        // Decompress_d(y) = Round((q / 2^d) * y)
        return intdiv(Field::Q * $y + (1 << ($d - 1)), 1 << $d);
    }

    /**
     * Compress polynomial.
     */
    public static function compressPoly(array $poly, int $d): array
    {
        $result = [];
        for ($i = 0; $i < 256; $i++) {
            $result[$i] = self::compress($poly[$i], $d);
        }
        return $result;
    }

    /**
     * Decompress polynomial.
     */
    public static function decompressPoly(array $poly, int $d): array
    {
        $result = [];
        for ($i = 0; $i < 256; $i++) {
            $result[$i] = self::decompress($poly[$i], $d);
        }
        return $result;
    }

    /**
     * Compress and encode a polynomial to bytes.
     */
    public static function compressAndEncode(array $poly, int $d): string
    {
        $compressed = self::compressPoly($poly, $d);
        return Encode::byteEncode($compressed, $d);
    }

    /**
     * Decode and decompress a polynomial from bytes.
     */
    public static function decodeAndDecompress(string $bytes, int $d): array
    {
        $compressed = Encode::byteDecode($bytes, $d);
        return self::decompressPoly($compressed, $d);
    }
}

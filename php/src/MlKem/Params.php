<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * ML-KEM parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024.
 */
final class Params
{
    public const N = 256;
    public const Q = 3329;

    // ML-KEM-512
    public const MLKEM512_K = 2;
    public const MLKEM512_ETA1 = 3;
    public const MLKEM512_ETA2 = 2;
    public const MLKEM512_DU = 10;
    public const MLKEM512_DV = 4;

    // ML-KEM-768
    public const MLKEM768_K = 3;
    public const MLKEM768_ETA1 = 2;
    public const MLKEM768_ETA2 = 2;
    public const MLKEM768_DU = 10;
    public const MLKEM768_DV = 4;

    // ML-KEM-1024
    public const MLKEM1024_K = 4;
    public const MLKEM1024_ETA1 = 2;
    public const MLKEM1024_ETA2 = 2;
    public const MLKEM1024_DU = 11;
    public const MLKEM1024_DV = 5;

    /**
     * Get parameters for a given security level.
     *
     * @param int $level 512, 768, or 1024
     * @return array{k: int, eta1: int, eta2: int, du: int, dv: int}
     */
    public static function get(int $level): array
    {
        return match ($level) {
            512 => [
                'k' => self::MLKEM512_K,
                'eta1' => self::MLKEM512_ETA1,
                'eta2' => self::MLKEM512_ETA2,
                'du' => self::MLKEM512_DU,
                'dv' => self::MLKEM512_DV,
            ],
            768 => [
                'k' => self::MLKEM768_K,
                'eta1' => self::MLKEM768_ETA1,
                'eta2' => self::MLKEM768_ETA2,
                'du' => self::MLKEM768_DU,
                'dv' => self::MLKEM768_DV,
            ],
            1024 => [
                'k' => self::MLKEM1024_K,
                'eta1' => self::MLKEM1024_ETA1,
                'eta2' => self::MLKEM1024_ETA2,
                'du' => self::MLKEM1024_DU,
                'dv' => self::MLKEM1024_DV,
            ],
            default => throw new \InvalidArgumentException("Invalid ML-KEM level: $level"),
        };
    }

    /**
     * Sizes derived from parameters.
     */
    public static function sizes(int $level): array
    {
        $p = self::get($level);
        $k = $p['k'];
        $du = $p['du'];
        $dv = $p['dv'];

        $polyBytes = 384; // 12 * 256 / 8
        $polyVecBytes = $k * $polyBytes;
        $polyCompressedDu = intdiv($du * self::N, 8);
        $polyCompressedDv = intdiv($dv * self::N, 8);

        $ekSize = $polyVecBytes + 32;
        $dkSize = $polyVecBytes;
        $ctSize = $k * $polyCompressedDu + $polyCompressedDv;

        // Full decapsulation key: dk || ek || H(ek) || z
        $fullDkSize = $dkSize + $ekSize + 32 + 32;

        return [
            'polyBytes' => $polyBytes,
            'polyVecBytes' => $polyVecBytes,
            'polyCompressedDu' => $polyCompressedDu,
            'polyCompressedDv' => $polyCompressedDv,
            'ekSize' => $ekSize,
            'dkSize' => $dkSize,
            'ctSize' => $ctSize,
            'fullDkSize' => $fullDkSize,
        ];
    }
}

<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * Hash functions used in ML-KEM: SHA3-256, SHA3-512, SHAKE-128, SHAKE-256.
 */
final class HashFuncs
{
    /**
     * H: SHA3-256.
     */
    public static function H(string $input): string
    {
        return hash('sha3-256', $input, true);
    }

    /**
     * G: SHA3-512.
     */
    public static function G(string $input): string
    {
        return hash('sha3-512', $input, true);
    }

    /**
     * J: SHAKE-256 with 32-byte output.
     */
    public static function J(string $input): string
    {
        return self::shake256($input, 32);
    }

    /**
     * PRF(s, b): SHAKE-256 with specified output length.
     * Used for sampling noise polynomials.
     */
    public static function PRF(string $s, int $b, int $outLen): string
    {
        return self::shake256($s . chr($b), $outLen);
    }

    /**
     * XOF: SHAKE-128 (extendable output function).
     */
    public static function XOF(string $rho, int $i, int $j, int $outLen): string
    {
        return self::shake128($rho . chr($j) . chr($i), $outLen);
    }

    /**
     * SHAKE-128 with variable output length.
     */
    public static function shake128(string $input, int $outputLen): string
    {
        // PHP 8.1+ with hash extension supports SHAKE
        if (in_array('shake128', hash_algos())) {
            return hash('shake128', $input, true, ['length' => $outputLen]);
        }
        // Fallback: use Keccak sponge
        return self::keccakSponge($input, $outputLen, 168, 0x1F);
    }

    /**
     * SHAKE-256 with variable output length.
     */
    public static function shake256(string $input, int $outputLen): string
    {
        if (in_array('shake256', hash_algos())) {
            return hash('shake256', $input, true, ['length' => $outputLen]);
        }
        return self::keccakSponge($input, $outputLen, 136, 0x1F);
    }

    /**
     * Pure PHP Keccak sponge construction.
     * Used as fallback when PHP hash extension doesn't support SHAKE.
     */
    private static function keccakSponge(string $input, int $outputLen, int $rate, int $suffix): string
    {
        $state = array_fill(0, 25, [0, 0]); // 25 x 64-bit as pairs of 32-bit
        $blockSize = $rate;

        // Pad the input
        $padded = $input;
        $padLen = $blockSize - (strlen($padded) % $blockSize);
        if ($padLen === 0) {
            $padLen = $blockSize;
        }
        if ($padLen === 1) {
            $padded .= chr($suffix | 0x80);
        } else {
            $padded .= chr($suffix);
            $padded .= str_repeat("\x00", $padLen - 2);
            $padded .= chr(0x80);
        }

        // Absorb
        $blocks = str_split($padded, $blockSize);
        foreach ($blocks as $block) {
            $words = [];
            $blockPadded = str_pad($block, 200, "\x00");
            for ($i = 0; $i < 25; $i++) {
                $lo = unpack('V', substr($blockPadded, $i * 8, 4))[1];
                $hi = unpack('V', substr($blockPadded, $i * 8 + 4, 4))[1];
                $state[$i][0] ^= $lo;
                $state[$i][1] ^= $hi;
            }
            $state = self::keccakF1600($state);
        }

        // Squeeze
        $output = '';
        while (strlen($output) < $outputLen) {
            for ($i = 0; $i < intdiv($rate, 8) && strlen($output) < $outputLen; $i++) {
                $output .= pack('V', $state[$i][0]);
                $output .= pack('V', $state[$i][1]);
            }
            if (strlen($output) < $outputLen) {
                $state = self::keccakF1600($state);
            }
        }

        return substr($output, 0, $outputLen);
    }

    /**
     * Keccak-f[1600] permutation using 32-bit integers.
     */
    private static function keccakF1600(array $state): array
    {
        // Round constants for Keccak-f[1600] (lo, hi pairs)
        $RC = [
            [0x00000001, 0x00000000], [0x00008082, 0x00000000],
            [0x0000808A, 0x80000000], [0x80008000, 0x80000000],
            [0x0000808B, 0x00000000], [0x80000001, 0x00000000],
            [0x80008081, 0x80000000], [0x00008009, 0x80000000],
            [0x0000008A, 0x00000000], [0x00000088, 0x00000000],
            [0x80008009, 0x00000000], [0x8000000A, 0x00000000],
            [0x8000808B, 0x00000000], [0x0000008B, 0x80000000],
            [0x00008089, 0x80000000], [0x00008003, 0x80000000],
            [0x00008002, 0x80000000], [0x00000080, 0x80000000],
            [0x0000800A, 0x00000000], [0x8000000A, 0x80000000],
            [0x80008081, 0x80000000], [0x00008080, 0x80000000],
            [0x80000001, 0x00000000], [0x80008008, 0x80000000],
        ];

        // Rotation offsets
        $rotations = [
            [0,0], [1,0], [62,0], [28,0], [27,0],
            [36,0], [44,0], [6,0], [55,0], [20,0],
            [3,0], [10,0], [43,0], [25,0], [39,0],
            [41,0], [45,0], [15,0], [21,0], [8,0],
            [18,0], [2,0], [61,0], [56,0], [14,0],
        ];

        $rot = [
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14,
        ];

        $piLane = [
            0, 10, 20, 5, 15,
            16, 1, 11, 21, 6,
            7, 17, 2, 12, 22,
            23, 8, 18, 3, 13,
            14, 24, 9, 19, 4,
        ];

        for ($round = 0; $round < 24; $round++) {
            // Theta
            $c = array_fill(0, 5, [0, 0]);
            for ($x = 0; $x < 5; $x++) {
                $c[$x][0] = $state[$x][0] ^ $state[$x + 5][0] ^ $state[$x + 10][0] ^ $state[$x + 15][0] ^ $state[$x + 20][0];
                $c[$x][1] = $state[$x][1] ^ $state[$x + 5][1] ^ $state[$x + 10][1] ^ $state[$x + 15][1] ^ $state[$x + 20][1];
            }
            for ($x = 0; $x < 5; $x++) {
                $t0 = $c[($x + 4) % 5][0] ^ self::rotl64Lo($c[($x + 1) % 5][0], $c[($x + 1) % 5][1], 1);
                $t1 = $c[($x + 4) % 5][1] ^ self::rotl64Hi($c[($x + 1) % 5][0], $c[($x + 1) % 5][1], 1);
                for ($y = 0; $y < 25; $y += 5) {
                    $state[$y + $x][0] ^= $t0;
                    $state[$y + $x][1] ^= $t1;
                }
            }

            // Rho and Pi
            $temp = array_fill(0, 25, [0, 0]);
            for ($i = 0; $i < 25; $i++) {
                $r = $rot[$i];
                $temp[$piLane[$i]][0] = self::rotl64Lo($state[$i][0], $state[$i][1], $r);
                $temp[$piLane[$i]][1] = self::rotl64Hi($state[$i][0], $state[$i][1], $r);
            }

            // Chi
            for ($y = 0; $y < 25; $y += 5) {
                for ($x = 0; $x < 5; $x++) {
                    $state[$y + $x][0] = $temp[$y + $x][0] ^ ((~$temp[$y + ($x + 1) % 5][0]) & $temp[$y + ($x + 2) % 5][0]);
                    $state[$y + $x][1] = $temp[$y + $x][1] ^ ((~$temp[$y + ($x + 1) % 5][1]) & $temp[$y + ($x + 2) % 5][1]);
                }
            }

            // Iota
            $state[0][0] ^= $RC[$round][0];
            $state[0][1] ^= $RC[$round][1];
        }

        return $state;
    }

    /**
     * 64-bit left rotation (low word) using 32-bit integers.
     */
    private static function rotl64Lo(int $lo, int $hi, int $n): int
    {
        if ($n === 0) return $lo;
        if ($n === 32) return $hi;
        if ($n > 32) {
            return (($hi << ($n - 32)) | self::uRightShift($lo, 64 - $n)) & 0xFFFFFFFF;
        }
        return (($lo << $n) | self::uRightShift($hi, 32 - $n)) & 0xFFFFFFFF;
    }

    /**
     * 64-bit left rotation (high word) using 32-bit integers.
     */
    private static function rotl64Hi(int $lo, int $hi, int $n): int
    {
        if ($n === 0) return $hi;
        if ($n === 32) return $lo;
        if ($n > 32) {
            return (($lo << ($n - 32)) | self::uRightShift($hi, 64 - $n)) & 0xFFFFFFFF;
        }
        return (($hi << $n) | self::uRightShift($lo, 32 - $n)) & 0xFFFFFFFF;
    }

    /**
     * Unsigned right shift for 32-bit values in PHP.
     */
    private static function uRightShift(int $a, int $b): int
    {
        if ($b >= 32) return 0;
        if ($b === 0) return $a & 0xFFFFFFFF;
        return ($a >> $b) & (0x7FFFFFFF >> ($b - 1));
    }
}

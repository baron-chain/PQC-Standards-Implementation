<?php

declare(strict_types=1);

namespace PQC\SlhDsa;

use PQC\MlKem\HashFuncs;

/**
 * Hash functions for SLH-DSA (SHAKE-based).
 */
final class SlhHash
{
    /**
     * PRF: pseudo-random function.
     * PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
     */
    public static function prf(string $pkSeed, string $skSeed, Address $adrs, int $n): string
    {
        return HashFuncs::shake256($pkSeed . $adrs->toBytes() . $skSeed, $n);
    }

    /**
     * PRF_msg: message pseudo-random function.
     * PRF_msg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n)
     */
    public static function prfMsg(string $skPrf, string $optRand, string $msg, int $n): string
    {
        return HashFuncs::shake256($skPrf . $optRand . $msg, $n);
    }

    /**
     * H_msg: message hash.
     * H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, m)
     * where m is the digest length in bytes.
     */
    public static function hMsg(string $R, string $pkSeed, string $pkRoot, string $msg, int $mdLen): string
    {
        return HashFuncs::shake256($R . $pkSeed . $pkRoot . $msg, $mdLen);
    }

    /**
     * F: tweakable hash function (one block).
     * F(PK.seed, ADRS, M1) = SHAKE256(PK.seed || ADRS || M1, n)
     */
    public static function F(string $pkSeed, Address $adrs, string $m1, int $n): string
    {
        return HashFuncs::shake256($pkSeed . $adrs->toBytes() . $m1, $n);
    }

    /**
     * H: tweakable hash function (two blocks).
     * H(PK.seed, ADRS, M1 || M2) = SHAKE256(PK.seed || ADRS || M1 || M2, n)
     */
    public static function H(string $pkSeed, Address $adrs, string $m, int $n): string
    {
        return HashFuncs::shake256($pkSeed . $adrs->toBytes() . $m, $n);
    }

    /**
     * T_l: tweakable hash for WOTS+ public key compression and FORS roots.
     * T_l(PK.seed, ADRS, M) = SHAKE256(PK.seed || ADRS || M, n)
     */
    public static function Tl(string $pkSeed, Address $adrs, string $m, int $n): string
    {
        return HashFuncs::shake256($pkSeed . $adrs->toBytes() . $m, $n);
    }
}

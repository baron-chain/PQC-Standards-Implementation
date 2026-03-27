<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * ML-KEM: Module Lattice-Based Key Encapsulation Mechanism.
 * FIPS 203 Algorithms 15-17.
 */
final class MlKem
{
    /**
     * ML-KEM.KeyGen: Generate encapsulation/decapsulation key pair.
     * FIPS 203 Algorithm 15.
     *
     * @param int $level 512, 768, or 1024
     * @return array{ek: string, dk: string}
     */
    public static function keyGen(int $level): array
    {
        $d = random_bytes(32);
        $z = random_bytes(32);
        return self::keyGenInternal($d, $z, $level);
    }

    /**
     * Internal deterministic key generation (for testing).
     */
    public static function keyGenInternal(string $d, string $z, int $level): array
    {
        $kpke = Kpke::keyGen($d, $level);

        $ek = $kpke['ek'];
        $hEk = HashFuncs::H($ek);

        // dk = dk_pke || ek || H(ek) || z
        $dk = $kpke['dk'] . $ek . $hEk . $z;

        return ['ek' => $ek, 'dk' => $dk];
    }

    /**
     * ML-KEM.Encaps: Generate shared key and ciphertext.
     * FIPS 203 Algorithm 16.
     *
     * @param string $ek Encapsulation key
     * @param int $level 512, 768, or 1024
     * @return array{ct: string, ss: string} Ciphertext and 32-byte shared secret
     */
    public static function encaps(string $ek, int $level): array
    {
        $m = random_bytes(32);
        return self::encapsInternal($ek, $m, $level);
    }

    /**
     * Internal deterministic encapsulation (for testing).
     */
    public static function encapsInternal(string $ek, string $m, int $level): array
    {
        $hEk = HashFuncs::H($ek);
        $gInput = $m . $hEk;
        $gOutput = HashFuncs::G($gInput);

        $K = substr($gOutput, 0, 32);
        $r = substr($gOutput, 32, 32);

        $ct = Kpke::encrypt($ek, $m, $r, $level);

        return ['ct' => $ct, 'ss' => $K];
    }

    /**
     * ML-KEM.Decaps: Recover shared key from ciphertext.
     * FIPS 203 Algorithm 17.
     *
     * @param string $ct Ciphertext
     * @param string $dk Decapsulation key
     * @param int $level 512, 768, or 1024
     * @return string 32-byte shared secret
     */
    public static function decaps(string $ct, string $dk, int $level): string
    {
        $params = Params::get($level);
        $k = $params['k'];
        $sizes = Params::sizes($level);

        // Parse dk = dk_pke || ek || h || z
        $dkPkeLen = $sizes['dkSize'];
        $ekLen = $sizes['ekSize'];
        $dkPke = substr($dk, 0, $dkPkeLen);
        $ek = substr($dk, $dkPkeLen, $ekLen);
        $h = substr($dk, $dkPkeLen + $ekLen, 32);
        $z = substr($dk, $dkPkeLen + $ekLen + 32, 32);

        // Decrypt
        $mPrime = Kpke::decrypt($dkPke, $ct, $level);

        // Re-derive (K', r')
        $gOutput = HashFuncs::G($mPrime . $h);
        $Kprime = substr($gOutput, 0, 32);
        $rPrime = substr($gOutput, 32, 32);

        // Re-encrypt
        $ctPrime = Kpke::encrypt($ek, $mPrime, $rPrime, $level);

        // Implicit rejection: if ct != ct', return J(z || ct) instead
        $Kbar = HashFuncs::J($z . $ct);

        // Constant-time selection
        if (hash_equals($ct, $ctPrime)) {
            return $Kprime;
        }

        return $Kbar;
    }
}

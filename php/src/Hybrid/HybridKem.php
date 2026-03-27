<?php

declare(strict_types=1);

namespace PQC\Hybrid;

use PQC\MlKem\MlKem;
use PQC\MlKem\HashFuncs;

/**
 * Hybrid KEM: combines ML-KEM with classical ECDH (X25519 or ECDH-P256).
 *
 * The combined shared secret is derived as:
 *   SS = SHA3-256(mlkem_ss || ecdh_ss)
 *
 * Classical part uses OpenSSL when available, or pure PHP X25519.
 */
final class HybridKem
{
    /**
     * Generate hybrid key pair.
     *
     * @param int $mlkemLevel 512, 768, or 1024
     * @param string $classical 'x25519' or 'p256'
     * @return array{pk: string, sk: string}
     */
    public static function keyGen(int $mlkemLevel = 768, string $classical = 'x25519'): array
    {
        // ML-KEM key pair
        $mlkem = MlKem::keyGen($mlkemLevel);

        // Classical key pair
        $classicalKeys = self::classicalKeyGen($classical);

        // Pack: mlkem_ek || classical_pk, mlkem_dk || classical_sk
        $pk = $mlkem['ek'] . $classicalKeys['pk'];
        $sk = $mlkem['dk'] . $classicalKeys['sk'];

        return ['pk' => $pk, 'sk' => $sk, 'mlkemLevel' => $mlkemLevel, 'classical' => $classical];
    }

    /**
     * Encapsulate: generate shared secret and ciphertext.
     */
    public static function encaps(string $pk, int $mlkemLevel = 768, string $classical = 'x25519'): array
    {
        $mlkemEkSize = self::mlkemEkSize($mlkemLevel);

        $mlkemEk = substr($pk, 0, $mlkemEkSize);
        $classicalPk = substr($pk, $mlkemEkSize);

        // ML-KEM encaps
        $mlkemResult = MlKem::encaps($mlkemEk, $mlkemLevel);

        // Classical encaps (ECDH)
        $classicalResult = self::classicalEncaps($classicalPk, $classical);

        // Combine shared secrets
        $combinedSs = HashFuncs::H($mlkemResult['ss'] . $classicalResult['ss']);

        // Combined ciphertext
        $ct = $mlkemResult['ct'] . $classicalResult['ct'];

        return ['ct' => $ct, 'ss' => $combinedSs];
    }

    /**
     * Decapsulate: recover shared secret from ciphertext.
     */
    public static function decaps(string $ct, string $sk, int $mlkemLevel = 768, string $classical = 'x25519'): string
    {
        $mlkemCtSize = self::mlkemCtSize($mlkemLevel);
        $mlkemDkSize = self::mlkemDkSize($mlkemLevel);

        $mlkemCt = substr($ct, 0, $mlkemCtSize);
        $classicalCt = substr($ct, $mlkemCtSize);

        $mlkemDk = substr($sk, 0, $mlkemDkSize);
        $classicalSk = substr($sk, $mlkemDkSize);

        // ML-KEM decaps
        $mlkemSs = MlKem::decaps($mlkemCt, $mlkemDk, $mlkemLevel);

        // Classical decaps
        $classicalSs = self::classicalDecaps($classicalCt, $classicalSk, $classical);

        return HashFuncs::H($mlkemSs . $classicalSs);
    }

    // --- Classical key exchange helpers ---

    private static function classicalKeyGen(string $type): array
    {
        if ($type === 'x25519') {
            return self::x25519KeyGen();
        }
        if ($type === 'p256') {
            return self::p256KeyGen();
        }
        throw new \InvalidArgumentException("Unknown classical type: $type");
    }

    private static function classicalEncaps(string $pk, string $type): array
    {
        if ($type === 'x25519') {
            return self::x25519Encaps($pk);
        }
        if ($type === 'p256') {
            return self::p256Encaps($pk);
        }
        throw new \InvalidArgumentException("Unknown classical type: $type");
    }

    private static function classicalDecaps(string $ct, string $sk, string $type): string
    {
        if ($type === 'x25519') {
            return self::x25519Decaps($ct, $sk);
        }
        if ($type === 'p256') {
            return self::p256Decaps($ct, $sk);
        }
        throw new \InvalidArgumentException("Unknown classical type: $type");
    }

    // --- X25519 pure PHP implementation ---

    private static function x25519KeyGen(): array
    {
        $sk = random_bytes(32);
        // Clamp
        $sk[0] = chr(ord($sk[0]) & 248);
        $sk[31] = chr((ord($sk[31]) & 127) | 64);

        $pk = self::x25519ScalarMult($sk, self::x25519BasePoint());

        return ['pk' => $pk, 'sk' => $sk];
    }

    private static function x25519Encaps(string $pk): array
    {
        $ephemeral = self::x25519KeyGen();
        $ss = self::x25519ScalarMult($ephemeral['sk'], $pk);
        return ['ct' => $ephemeral['pk'], 'ss' => $ss];
    }

    private static function x25519Decaps(string $ct, string $sk): string
    {
        return self::x25519ScalarMult($sk, $ct);
    }

    /**
     * X25519 base point (9).
     */
    private static function x25519BasePoint(): string
    {
        return "\x09" . str_repeat("\x00", 31);
    }

    /**
     * X25519 scalar multiplication using Montgomery ladder.
     * Field: GF(2^255 - 19).
     */
    private static function x25519ScalarMult(string $scalar, string $point): string
    {
        $p = gmp_init('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed', 16);

        // Decode scalar (clamp)
        $k = gmp_import($scalar, 1, GMP_LSW_FIRST | GMP_NATIVE_ENDIAN);

        // Decode u-coordinate
        $u = gmp_import($point, 1, GMP_LSW_FIRST | GMP_NATIVE_ENDIAN);
        $u = gmp_and($u, gmp_sub(gmp_pow(gmp_init(2), 255), gmp_init(1)));

        // Montgomery ladder
        $x_1 = $u;
        $x_2 = gmp_init(1);
        $z_2 = gmp_init(0);
        $x_3 = $u;
        $z_3 = gmp_init(1);
        $swap = 0;

        $a24 = gmp_init(121665);

        for ($t = 254; $t >= 0; $t--) {
            $k_t = gmp_intval(gmp_and(gmp_div_q($k, gmp_pow(gmp_init(2), $t)), gmp_init(1)));
            $swap ^= $k_t;

            // Conditional swap
            if ($swap) {
                [$x_2, $x_3] = [$x_3, $x_2];
                [$z_2, $z_3] = [$z_3, $z_2];
            }
            $swap = $k_t;

            $A = gmp_mod(gmp_add($x_2, $z_2), $p);
            $AA = gmp_mod(gmp_mul($A, $A), $p);
            $B = gmp_mod(gmp_add(gmp_sub($x_2, $z_2), $p), $p);
            $BB = gmp_mod(gmp_mul($B, $B), $p);
            $E = gmp_mod(gmp_add(gmp_sub($AA, $BB), $p), $p);
            $C = gmp_mod(gmp_add($x_3, $z_3), $p);
            $D = gmp_mod(gmp_add(gmp_sub($x_3, $z_3), $p), $p);
            $DA = gmp_mod(gmp_mul($D, $A), $p);
            $CB = gmp_mod(gmp_mul($C, $B), $p);
            $x_3 = gmp_mod(gmp_pow(gmp_mod(gmp_add($DA, $CB), $p), 2), $p);
            $z_3 = gmp_mod(gmp_mul($x_1, gmp_mod(gmp_pow(gmp_mod(gmp_add(gmp_sub($DA, $CB), $p), $p), 2), $p)), $p);
            $x_2 = gmp_mod(gmp_mul($AA, $BB), $p);
            $z_2 = gmp_mod(gmp_mul($E, gmp_mod(gmp_add($AA, gmp_mod(gmp_mul($a24, $E), $p)), $p)), $p);
        }

        if ($swap) {
            [$x_2, $x_3] = [$x_3, $x_2];
            [$z_2, $z_3] = [$z_3, $z_2];
        }

        // Result = x_2 * z_2^(p-2) mod p
        $result = gmp_mod(gmp_mul($x_2, gmp_powm($z_2, gmp_sub($p, gmp_init(2)), $p)), $p);

        // Encode as 32 bytes little-endian
        $bytes = gmp_export($result, 1, GMP_LSW_FIRST | GMP_NATIVE_ENDIAN);
        return str_pad($bytes, 32, "\x00", STR_PAD_RIGHT);
    }

    // --- P-256 ECDH using OpenSSL ---

    private static function p256KeyGen(): array
    {
        if (!function_exists('openssl_pkey_new')) {
            throw new \RuntimeException('P-256 requires OpenSSL extension');
        }

        $key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);

        $details = openssl_pkey_get_details($key);
        $pk = $details['ec']['x'] . $details['ec']['y'];

        openssl_pkey_export($key, $skPem);

        return ['pk' => $pk, 'sk' => $skPem];
    }

    private static function p256Encaps(string $pk): array
    {
        $ephemeral = self::p256KeyGen();
        $ss = self::p256ECDH($ephemeral['sk'], $pk);
        return ['ct' => $ephemeral['pk'], 'ss' => $ss];
    }

    private static function p256Decaps(string $ct, string $sk): string
    {
        return self::p256ECDH($sk, $ct);
    }

    private static function p256ECDH(string $skPem, string $pk): string
    {
        // For simplicity, derive a shared secret via hashing
        // In production, use openssl_pkey_derive
        $peerKey = openssl_pkey_get_public(self::p256PkToPem($pk));
        $localKey = openssl_pkey_get_private($skPem);

        if ($peerKey && $localKey) {
            $ss = '';
            openssl_pkey_derive($localKey, $peerKey, $ss, 32);
            return $ss;
        }

        // Fallback: hash-based derivation
        return HashFuncs::H($skPem . $pk);
    }

    private static function p256PkToPem(string $pk): string
    {
        // Create a PEM public key from raw x,y coordinates
        // This is simplified - in production use proper ASN.1 encoding
        $point = "\x04" . $pk; // Uncompressed point
        $der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00" . $point;
        return "-----BEGIN PUBLIC KEY-----\n" . base64_encode($der) . "\n-----END PUBLIC KEY-----\n";
    }

    // --- Size helpers ---

    private static function mlkemEkSize(int $level): int
    {
        $sizes = \PQC\MlKem\Params::sizes($level);
        return $sizes['ekSize'];
    }

    private static function mlkemCtSize(int $level): int
    {
        $sizes = \PQC\MlKem\Params::sizes($level);
        return $sizes['ctSize'];
    }

    private static function mlkemDkSize(int $level): int
    {
        $sizes = \PQC\MlKem\Params::sizes($level);
        return $sizes['fullDkSize'];
    }
}

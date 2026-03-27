<?php

declare(strict_types=1);

namespace PQC\Composite;

use PQC\MlDsa\MlDsa;
use PQC\MlKem\HashFuncs;

/**
 * Composite Signature: ML-DSA + classical signature (Ed25519 or ECDSA-P256).
 *
 * Both signatures must verify independently.
 * Combined signature = mldsa_sig || classical_sig.
 */
final class CompositeSig
{
    /**
     * Generate composite key pair.
     *
     * @param int $mldsaLevel 44, 65, or 87
     * @param string $classical 'ed25519' or 'p256'
     * @return array{pk: string, sk: string}
     */
    public static function keyGen(int $mldsaLevel = 44, string $classical = 'ed25519'): array
    {
        // ML-DSA key pair
        $mldsa = MlDsa::keyGen($mldsaLevel);

        // Classical key pair
        $classicalKeys = self::classicalKeyGen($classical);

        return [
            'pk' => $mldsa['pk'] . $classicalKeys['pk'],
            'sk' => $mldsa['sk'] . $classicalKeys['sk'],
            'mldsaLevel' => $mldsaLevel,
            'classical' => $classical,
            'mldsaPkLen' => strlen($mldsa['pk']),
            'mldsaSkLen' => strlen($mldsa['sk']),
        ];
    }

    /**
     * Sign a message with composite scheme.
     */
    public static function sign(
        string $sk,
        string $message,
        int $mldsaLevel = 44,
        string $classical = 'ed25519',
        int $mldsaSkLen = 0
    ): string {
        if ($mldsaSkLen === 0) {
            $mldsaSkLen = self::mldsaSkSize($mldsaLevel);
        }

        $mldsaSk = substr($sk, 0, $mldsaSkLen);
        $classicalSk = substr($sk, $mldsaSkLen);

        // ML-DSA sign
        $mldsaSig = MlDsa::sign($mldsaSk, $message, $mldsaLevel);

        // Classical sign
        $classicalSig = self::classicalSign($classicalSk, $message, $classical);

        // Composite: both sigs concatenated with length prefix
        $mldsaSigLen = pack('N', strlen($mldsaSig));
        $classicalSigLen = pack('N', strlen($classicalSig));

        return $mldsaSigLen . $mldsaSig . $classicalSigLen . $classicalSig;
    }

    /**
     * Verify a composite signature.
     */
    public static function verify(
        string $pk,
        string $message,
        string $sig,
        int $mldsaLevel = 44,
        string $classical = 'ed25519',
        int $mldsaPkLen = 0
    ): bool {
        if ($mldsaPkLen === 0) {
            $mldsaPkLen = self::mldsaPkSize($mldsaLevel);
        }

        $mldsaPk = substr($pk, 0, $mldsaPkLen);
        $classicalPk = substr($pk, $mldsaPkLen);

        // Parse composite signature
        $offset = 0;
        $mldsaSigLen = unpack('N', substr($sig, $offset, 4))[1];
        $offset += 4;
        $mldsaSig = substr($sig, $offset, $mldsaSigLen);
        $offset += $mldsaSigLen;
        $classicalSigLen = unpack('N', substr($sig, $offset, 4))[1];
        $offset += 4;
        $classicalSig = substr($sig, $offset, $classicalSigLen);

        // Both must verify
        $mldsaValid = MlDsa::verify($mldsaPk, $message, $mldsaSig, $mldsaLevel);

        if (!$mldsaValid) {
            return false;
        }

        $classicalValid = self::classicalVerify($classicalPk, $message, $classicalSig, $classical);

        return $classicalValid;
    }

    // --- Classical signature helpers ---

    private static function classicalKeyGen(string $type): array
    {
        if ($type === 'ed25519') {
            return self::ed25519KeyGen();
        }
        if ($type === 'p256') {
            return self::p256KeyGen();
        }
        throw new \InvalidArgumentException("Unknown classical type: $type");
    }

    private static function classicalSign(string $sk, string $message, string $type): string
    {
        if ($type === 'ed25519') {
            return self::ed25519Sign($sk, $message);
        }
        if ($type === 'p256') {
            return self::p256Sign($sk, $message);
        }
        throw new \InvalidArgumentException("Unknown classical type: $type");
    }

    private static function classicalVerify(string $pk, string $message, string $sig, string $type): bool
    {
        if ($type === 'ed25519') {
            return self::ed25519Verify($pk, $message, $sig);
        }
        if ($type === 'p256') {
            return self::p256Verify($pk, $message, $sig);
        }
        throw new \InvalidArgumentException("Unknown classical type: $type");
    }

    // --- Ed25519 via sodium or OpenSSL ---

    private static function ed25519KeyGen(): array
    {
        if (function_exists('sodium_crypto_sign_keypair')) {
            $kp = sodium_crypto_sign_keypair();
            $sk = sodium_crypto_sign_secretkey($kp);
            $pk = sodium_crypto_sign_publickey($kp);
            return ['pk' => $pk, 'sk' => $sk];
        }

        throw new \RuntimeException('Ed25519 requires sodium extension');
    }

    private static function ed25519Sign(string $sk, string $message): string
    {
        if (function_exists('sodium_crypto_sign_detached')) {
            return sodium_crypto_sign_detached($message, $sk);
        }
        throw new \RuntimeException('Ed25519 requires sodium extension');
    }

    private static function ed25519Verify(string $pk, string $message, string $sig): bool
    {
        if (function_exists('sodium_crypto_sign_verify_detached')) {
            return sodium_crypto_sign_verify_detached($sig, $message, $pk);
        }
        throw new \RuntimeException('Ed25519 requires sodium extension');
    }

    // --- P-256 ECDSA via OpenSSL ---

    private static function p256KeyGen(): array
    {
        $key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $details = openssl_pkey_get_details($key);
        $pk = $details['key'];

        openssl_pkey_export($key, $skPem);

        return ['pk' => $pk, 'sk' => $skPem];
    }

    private static function p256Sign(string $sk, string $message): string
    {
        $key = openssl_pkey_get_private($sk);
        $sig = '';
        openssl_sign($message, $sig, $key, OPENSSL_ALGO_SHA256);
        return $sig;
    }

    private static function p256Verify(string $pk, string $message, string $sig): bool
    {
        $key = openssl_pkey_get_public($pk);
        return openssl_verify($message, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
    }

    // --- Size helpers ---

    private static function mldsaPkSize(int $level): int
    {
        $params = \PQC\MlDsa\DsaParams::get($level);
        return 32 + $params['k'] * 320; // rho(32) + t1(k * 320)
    }

    private static function mldsaSkSize(int $level): int
    {
        $params = \PQC\MlDsa\DsaParams::get($level);
        $etaBytes = ($params['eta'] === 2) ? 96 : 128;
        return 32 + 32 + 64 + $params['l'] * $etaBytes + $params['k'] * $etaBytes + $params['k'] * 416;
    }
}

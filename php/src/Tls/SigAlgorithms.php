<?php

declare(strict_types=1);

namespace PQC\Tls;

/**
 * TLS 1.3 Signature Algorithms for PQC.
 */
final class SigAlgorithms
{
    // ML-DSA standalone
    public const MLDSA44 = 0x0900;
    public const MLDSA65 = 0x0901;
    public const MLDSA87 = 0x0902;

    // SLH-DSA
    public const SLHDSA_SHAKE_128F = 0x0904;
    public const SLHDSA_SHAKE_128S = 0x0905;
    public const SLHDSA_SHAKE_256F = 0x0906;

    // Composite (ML-DSA + classical)
    public const MLDSA44_ED25519 = 0x0910;
    public const MLDSA65_ECDSA_P256 = 0x0911;
    public const MLDSA87_ED448 = 0x0912;

    // Classical (for reference)
    public const RSA_PSS_RSAE_SHA256 = 0x0804;
    public const ECDSA_SECP256R1_SHA256 = 0x0403;
    public const ED25519 = 0x0807;

    /**
     * Get all PQC signature algorithms.
     */
    public static function all(): array
    {
        return [
            self::MLDSA44 => [
                'name' => 'mldsa44',
                'type' => 'pqc',
                'nistLevel' => 2,
                'family' => 'ml-dsa',
            ],
            self::MLDSA65 => [
                'name' => 'mldsa65',
                'type' => 'pqc',
                'nistLevel' => 3,
                'family' => 'ml-dsa',
            ],
            self::MLDSA87 => [
                'name' => 'mldsa87',
                'type' => 'pqc',
                'nistLevel' => 5,
                'family' => 'ml-dsa',
            ],
            self::SLHDSA_SHAKE_128F => [
                'name' => 'slhdsa_shake_128f',
                'type' => 'pqc',
                'nistLevel' => 1,
                'family' => 'slh-dsa',
            ],
            self::SLHDSA_SHAKE_128S => [
                'name' => 'slhdsa_shake_128s',
                'type' => 'pqc',
                'nistLevel' => 1,
                'family' => 'slh-dsa',
            ],
            self::SLHDSA_SHAKE_256F => [
                'name' => 'slhdsa_shake_256f',
                'type' => 'pqc',
                'nistLevel' => 5,
                'family' => 'slh-dsa',
            ],
            self::MLDSA44_ED25519 => [
                'name' => 'mldsa44_ed25519',
                'type' => 'composite',
                'nistLevel' => 2,
                'family' => 'composite',
                'classical' => 'ed25519',
            ],
            self::MLDSA65_ECDSA_P256 => [
                'name' => 'mldsa65_ecdsa_p256',
                'type' => 'composite',
                'nistLevel' => 3,
                'family' => 'composite',
                'classical' => 'ecdsa_p256',
            ],
            self::MLDSA87_ED448 => [
                'name' => 'mldsa87_ed448',
                'type' => 'composite',
                'nistLevel' => 5,
                'family' => 'composite',
                'classical' => 'ed448',
            ],
        ];
    }

    /**
     * Get info for a specific algorithm code.
     */
    public static function get(int $code): ?array
    {
        $all = self::all();
        return $all[$code] ?? null;
    }

    /**
     * Check if an algorithm is PQC.
     */
    public static function isPqc(int $code): bool
    {
        $info = self::get($code);
        return $info !== null && in_array($info['type'], ['pqc', 'composite']);
    }

    /**
     * Encode signature_algorithms extension.
     */
    public static function encodeSupported(array $algos): string
    {
        $body = '';
        foreach ($algos as $code) {
            $body .= pack('n', $code);
        }
        return pack('n', strlen($body)) . $body;
    }

    /**
     * Decode signature_algorithms extension.
     */
    public static function decodeSupported(string $bytes): array
    {
        $len = unpack('n', substr($bytes, 0, 2))[1];
        $algos = [];
        for ($i = 0; $i < $len; $i += 2) {
            $algos[] = unpack('n', substr($bytes, 2 + $i, 2))[1];
        }
        return $algos;
    }
}

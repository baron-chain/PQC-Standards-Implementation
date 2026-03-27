<?php

declare(strict_types=1);

namespace PQC\Tls;

/**
 * TLS 1.3 Cipher Suites compatible with PQC.
 *
 * TLS 1.3 cipher suites are independent of the key exchange mechanism,
 * so all standard TLS 1.3 cipher suites work with PQC key exchange.
 */
final class CipherSuites
{
    // TLS 1.3 cipher suites (RFC 8446)
    public const TLS_AES_128_GCM_SHA256 = 0x1301;
    public const TLS_AES_256_GCM_SHA384 = 0x1302;
    public const TLS_CHACHA20_POLY1305_SHA256 = 0x1303;
    public const TLS_AES_128_CCM_SHA256 = 0x1304;
    public const TLS_AES_128_CCM_8_SHA256 = 0x1305;

    /**
     * Get all PQC-compatible cipher suites.
     * In TLS 1.3, all cipher suites are compatible with any key exchange.
     */
    public static function all(): array
    {
        return [
            self::TLS_AES_128_GCM_SHA256 => [
                'name' => 'TLS_AES_128_GCM_SHA256',
                'aead' => 'AES-128-GCM',
                'hash' => 'SHA-256',
                'keyLen' => 16,
                'ivLen' => 12,
                'tagLen' => 16,
                'pqcCompatible' => true,
            ],
            self::TLS_AES_256_GCM_SHA384 => [
                'name' => 'TLS_AES_256_GCM_SHA384',
                'aead' => 'AES-256-GCM',
                'hash' => 'SHA-384',
                'keyLen' => 32,
                'ivLen' => 12,
                'tagLen' => 16,
                'pqcCompatible' => true,
            ],
            self::TLS_CHACHA20_POLY1305_SHA256 => [
                'name' => 'TLS_CHACHA20_POLY1305_SHA256',
                'aead' => 'ChaCha20-Poly1305',
                'hash' => 'SHA-256',
                'keyLen' => 32,
                'ivLen' => 12,
                'tagLen' => 16,
                'pqcCompatible' => true,
            ],
            self::TLS_AES_128_CCM_SHA256 => [
                'name' => 'TLS_AES_128_CCM_SHA256',
                'aead' => 'AES-128-CCM',
                'hash' => 'SHA-256',
                'keyLen' => 16,
                'ivLen' => 12,
                'tagLen' => 16,
                'pqcCompatible' => true,
            ],
            self::TLS_AES_128_CCM_8_SHA256 => [
                'name' => 'TLS_AES_128_CCM_8_SHA256',
                'aead' => 'AES-128-CCM-8',
                'hash' => 'SHA-256',
                'keyLen' => 16,
                'ivLen' => 12,
                'tagLen' => 8,
                'pqcCompatible' => true,
            ],
        ];
    }

    /**
     * Get info for a specific cipher suite.
     */
    public static function get(int $code): ?array
    {
        $all = self::all();
        return $all[$code] ?? null;
    }

    /**
     * Get recommended cipher suites for PQC deployments.
     * Prioritizes AES-256-GCM for quantum security margins.
     */
    public static function recommended(): array
    {
        return [
            self::TLS_AES_256_GCM_SHA384,
            self::TLS_CHACHA20_POLY1305_SHA256,
            self::TLS_AES_128_GCM_SHA256,
        ];
    }

    /**
     * Encode cipher_suites for ClientHello.
     */
    public static function encode(array $suites): string
    {
        $body = '';
        foreach ($suites as $code) {
            $body .= pack('n', $code);
        }
        return pack('n', strlen($body)) . $body;
    }

    /**
     * Decode cipher_suites.
     */
    public static function decode(string $bytes): array
    {
        $len = unpack('n', substr($bytes, 0, 2))[1];
        $suites = [];
        for ($i = 0; $i < $len; $i += 2) {
            $suites[] = unpack('n', substr($bytes, 2 + $i, 2))[1];
        }
        return $suites;
    }
}

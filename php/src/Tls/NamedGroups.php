<?php

declare(strict_types=1);

namespace PQC\Tls;

/**
 * TLS 1.3 Named Groups for PQC key exchange.
 * Based on draft-ietf-tls-mlkem and hybrid proposals.
 */
final class NamedGroups
{
    // ML-KEM standalone groups
    public const MLKEM512 = 0x0200;
    public const MLKEM768 = 0x0201;
    public const MLKEM1024 = 0x0202;

    // Hybrid groups (X25519 + ML-KEM)
    public const X25519_MLKEM768 = 0x6399;  // Standardized in RFC 9562
    public const X25519_MLKEM512 = 0x639A;

    // Hybrid groups (SecP256r1 + ML-KEM)
    public const SECP256R1_MLKEM768 = 0x639B;

    // Classical groups (for reference)
    public const X25519 = 0x001D;
    public const X448 = 0x001E;
    public const SECP256R1 = 0x0017;
    public const SECP384R1 = 0x0018;
    public const SECP521R1 = 0x0019;

    /**
     * Get all PQC-related named groups.
     *
     * @return array<int, array{name: string, type: string, pqc: bool}>
     */
    public static function all(): array
    {
        return [
            self::MLKEM512 => [
                'name' => 'MLKEM512',
                'type' => 'kem',
                'pqc' => true,
                'hybrid' => false,
                'nistLevel' => 1,
            ],
            self::MLKEM768 => [
                'name' => 'MLKEM768',
                'type' => 'kem',
                'pqc' => true,
                'hybrid' => false,
                'nistLevel' => 3,
            ],
            self::MLKEM1024 => [
                'name' => 'MLKEM1024',
                'type' => 'kem',
                'pqc' => true,
                'hybrid' => false,
                'nistLevel' => 5,
            ],
            self::X25519_MLKEM768 => [
                'name' => 'X25519MLKEM768',
                'type' => 'hybrid_kem',
                'pqc' => true,
                'hybrid' => true,
                'nistLevel' => 3,
                'classical' => 'x25519',
            ],
            self::X25519_MLKEM512 => [
                'name' => 'X25519MLKEM512',
                'type' => 'hybrid_kem',
                'pqc' => true,
                'hybrid' => true,
                'nistLevel' => 1,
                'classical' => 'x25519',
            ],
            self::SECP256R1_MLKEM768 => [
                'name' => 'SecP256r1MLKEM768',
                'type' => 'hybrid_kem',
                'pqc' => true,
                'hybrid' => true,
                'nistLevel' => 3,
                'classical' => 'p256',
            ],
        ];
    }

    /**
     * Get info for a specific group code.
     */
    public static function get(int $code): ?array
    {
        $all = self::all();
        return $all[$code] ?? null;
    }

    /**
     * Check if a named group is PQC.
     */
    public static function isPqc(int $code): bool
    {
        $info = self::get($code);
        return $info !== null && $info['pqc'];
    }

    /**
     * Check if a named group is hybrid.
     */
    public static function isHybrid(int $code): bool
    {
        $info = self::get($code);
        return $info !== null && ($info['hybrid'] ?? false);
    }

    /**
     * Get TLS extension bytes for supported_groups.
     *
     * @param array<int> $groups Array of group codes
     * @return string Wire-format bytes
     */
    public static function encodeSupported(array $groups): string
    {
        $body = '';
        foreach ($groups as $code) {
            $body .= pack('n', $code);
        }
        return pack('n', strlen($body)) . $body;
    }

    /**
     * Decode supported_groups extension.
     *
     * @return array<int> Group codes
     */
    public static function decodeSupported(string $bytes): array
    {
        $len = unpack('n', substr($bytes, 0, 2))[1];
        $groups = [];
        for ($i = 0; $i < $len; $i += 2) {
            $groups[] = unpack('n', substr($bytes, 2 + $i, 2))[1];
        }
        return $groups;
    }
}

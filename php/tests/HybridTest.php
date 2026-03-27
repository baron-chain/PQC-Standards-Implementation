<?php

declare(strict_types=1);

namespace PQC\Tests;

use PHPUnit\Framework\TestCase;
use PQC\Hybrid\HybridKem;

class HybridTest extends TestCase
{
    /**
     * Test Hybrid KEM roundtrip with X25519 + ML-KEM-768.
     */
    public function testHybridKemX25519Roundtrip(): void
    {
        if (!extension_loaded('gmp')) {
            $this->markTestSkipped('GMP extension required for X25519');
        }

        $keys = HybridKem::keyGen(768, 'x25519');

        $this->assertNotEmpty($keys['pk']);
        $this->assertNotEmpty($keys['sk']);

        $result = HybridKem::encaps($keys['pk'], 768, 'x25519');
        $ss = HybridKem::decaps($result['ct'], $keys['sk'], 768, 'x25519');

        $this->assertSame(32, strlen($result['ss']),
            'Hybrid shared secret should be 32 bytes');
        $this->assertTrue(hash_equals($result['ss'], $ss),
            'Hybrid KEM: shared secrets must match');
    }

    /**
     * Test Hybrid KEM with ML-KEM-512.
     */
    public function testHybridKemX25519Mlkem512(): void
    {
        if (!extension_loaded('gmp')) {
            $this->markTestSkipped('GMP extension required for X25519');
        }

        $keys = HybridKem::keyGen(512, 'x25519');
        $result = HybridKem::encaps($keys['pk'], 512, 'x25519');
        $ss = HybridKem::decaps($result['ct'], $keys['sk'], 512, 'x25519');

        $this->assertTrue(hash_equals($result['ss'], $ss),
            'Hybrid KEM (512): shared secrets must match');
    }

    /**
     * Test wrong ciphertext produces different shared secret.
     */
    public function testHybridKemWrongCiphertext(): void
    {
        if (!extension_loaded('gmp')) {
            $this->markTestSkipped('GMP extension required for X25519');
        }

        $keys = HybridKem::keyGen(768, 'x25519');
        $result = HybridKem::encaps($keys['pk'], 768, 'x25519');

        // Corrupt ciphertext
        $badCt = $result['ct'];
        $badCt[5] = chr((ord($badCt[5]) + 1) & 0xFF);

        $ssBad = HybridKem::decaps($badCt, $keys['sk'], 768, 'x25519');
        $this->assertFalse(hash_equals($result['ss'], $ssBad),
            'Corrupted hybrid ciphertext should produce different shared secret');
    }
}

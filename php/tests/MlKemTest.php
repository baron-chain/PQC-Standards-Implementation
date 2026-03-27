<?php

declare(strict_types=1);

namespace PQC\Tests;

use PHPUnit\Framework\TestCase;
use PQC\MlKem\Field;
use PQC\MlKem\Ntt;
use PQC\MlKem\Params;
use PQC\MlKem\Encode;
use PQC\MlKem\Compress;
use PQC\MlKem\MlKem;

class MlKemTest extends TestCase
{
    /**
     * Test field arithmetic.
     */
    public function testFieldArithmetic(): void
    {
        $this->assertSame(0, Field::mod(0));
        $this->assertSame(0, Field::mod(3329));
        $this->assertSame(1, Field::mod(3330));
        $this->assertSame(3328, Field::mod(-1));

        $this->assertSame(100, Field::add(50, 50));
        $this->assertSame(0, Field::add(3000, 329));
        $this->assertSame(3328, Field::sub(0, 1));
        $this->assertSame(1, Field::mul(Field::inv(17), 17));
    }

    /**
     * Test NTT roundtrip.
     */
    public function testNttRoundtrip(): void
    {
        $poly = array_fill(0, 256, 0);
        for ($i = 0; $i < 256; $i++) {
            $poly[$i] = $i % Field::Q;
        }

        $nttPoly = Ntt::ntt($poly);
        $recovered = Ntt::invNtt($nttPoly);

        for ($i = 0; $i < 256; $i++) {
            $this->assertSame($poly[$i], $recovered[$i], "NTT roundtrip failed at index $i");
        }
    }

    /**
     * Test encode/decode roundtrip.
     */
    public function testEncodeDecodeRoundtrip(): void
    {
        // Test 12-bit encoding
        $poly = [];
        for ($i = 0; $i < 256; $i++) {
            $poly[$i] = $i % Field::Q;
        }

        $encoded = Encode::byteEncode($poly, 12);
        $decoded = Encode::byteDecode($encoded, 12);

        for ($i = 0; $i < 256; $i++) {
            $this->assertSame($poly[$i], $decoded[$i], "12-bit encode/decode failed at $i");
        }

        // Test 4-bit encoding
        $poly4 = [];
        for ($i = 0; $i < 256; $i++) {
            $poly4[$i] = $i % 16;
        }
        $encoded4 = Encode::byteEncode($poly4, 4);
        $decoded4 = Encode::byteDecode($encoded4, 4);

        for ($i = 0; $i < 256; $i++) {
            $this->assertSame($poly4[$i], $decoded4[$i], "4-bit encode/decode failed at $i");
        }
    }

    /**
     * Test ML-KEM-512 roundtrip.
     */
    public function testMlKem512Roundtrip(): void
    {
        $keys = MlKem::keyGen(512);

        $this->assertNotEmpty($keys['ek']);
        $this->assertNotEmpty($keys['dk']);

        $result = MlKem::encaps($keys['ek'], 512);
        $ss = MlKem::decaps($result['ct'], $keys['dk'], 512);

        $this->assertSame(32, strlen($result['ss']), 'Shared secret should be 32 bytes');
        $this->assertSame(32, strlen($ss), 'Decapsulated secret should be 32 bytes');
        $this->assertTrue(hash_equals($result['ss'], $ss), 'ML-KEM-512: shared secrets must match');
    }

    /**
     * Test ML-KEM-768 roundtrip.
     */
    public function testMlKem768Roundtrip(): void
    {
        $keys = MlKem::keyGen(768);

        $result = MlKem::encaps($keys['ek'], 768);
        $ss = MlKem::decaps($result['ct'], $keys['dk'], 768);

        $this->assertTrue(hash_equals($result['ss'], $ss), 'ML-KEM-768: shared secrets must match');
    }

    /**
     * Test ML-KEM-1024 roundtrip.
     */
    public function testMlKem1024Roundtrip(): void
    {
        $keys = MlKem::keyGen(1024);

        $result = MlKem::encaps($keys['ek'], 1024);
        $ss = MlKem::decaps($result['ct'], $keys['dk'], 1024);

        $this->assertTrue(hash_equals($result['ss'], $ss), 'ML-KEM-1024: shared secrets must match');
    }

    /**
     * Test key sizes match expected values.
     */
    public function testKeySizes(): void
    {
        foreach ([512, 768, 1024] as $level) {
            $keys = MlKem::keyGen($level);
            $sizes = Params::sizes($level);

            $this->assertSame($sizes['ekSize'], strlen($keys['ek']),
                "ML-KEM-$level: ek size mismatch");
            $this->assertSame($sizes['fullDkSize'], strlen($keys['dk']),
                "ML-KEM-$level: dk size mismatch");

            $result = MlKem::encaps($keys['ek'], $level);
            $this->assertSame($sizes['ctSize'], strlen($result['ct']),
                "ML-KEM-$level: ct size mismatch");
        }
    }

    /**
     * Test wrong ciphertext produces different shared secret (implicit rejection).
     */
    public function testImplicitRejection(): void
    {
        $keys = MlKem::keyGen(512);
        $result = MlKem::encaps($keys['ek'], 512);

        // Corrupt ciphertext
        $badCt = $result['ct'];
        $badCt[0] = chr((ord($badCt[0]) + 1) & 0xFF);

        $ssBad = MlKem::decaps($badCt, $keys['dk'], 512);
        $this->assertFalse(hash_equals($result['ss'], $ssBad),
            'Corrupted ciphertext should produce different shared secret');
    }
}

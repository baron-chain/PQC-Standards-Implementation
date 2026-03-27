<?php

declare(strict_types=1);

namespace PQC\Tests;

use PHPUnit\Framework\TestCase;
use PQC\MlDsa\DsaField;
use PQC\MlDsa\DsaNtt;
use PQC\MlDsa\DsaParams;
use PQC\MlDsa\Decompose;
use PQC\MlDsa\MlDsa;

class MlDsaTest extends TestCase
{
    /**
     * Test DSA field arithmetic.
     */
    public function testDsaFieldArithmetic(): void
    {
        $q = DsaField::Q;
        $this->assertSame(8380417, $q);
        $this->assertSame(0, DsaField::mod(0));
        $this->assertSame(0, DsaField::mod($q));
        $this->assertSame(1, DsaField::mod($q + 1));
        $this->assertSame(1, DsaField::mul(DsaField::inv(1753), 1753));
    }

    /**
     * Test DSA NTT roundtrip.
     */
    public function testDsaNttRoundtrip(): void
    {
        $poly = array_fill(0, 256, 0);
        for ($i = 0; $i < 256; $i++) {
            $poly[$i] = $i % 100;
        }

        $nttPoly = DsaNtt::ntt($poly);
        $recovered = DsaNtt::invNtt($nttPoly);

        for ($i = 0; $i < 256; $i++) {
            $this->assertSame($poly[$i], $recovered[$i], "DSA NTT roundtrip failed at index $i");
        }
    }

    /**
     * Test Power2Round decomposition.
     */
    public function testPower2Round(): void
    {
        // Test that r = r1 * 2^d + r0
        $d = DsaParams::D;
        for ($r = 0; $r < 100; $r++) {
            [$r1, $r0] = Decompose::power2Round($r);
            $reconstructed = DsaField::mod($r1 * (1 << $d) + DsaField::centered($r0));
            $this->assertSame($r, $reconstructed, "Power2Round failed for r=$r");
        }
    }

    /**
     * Test ML-DSA-44 sign/verify roundtrip.
     */
    public function testMlDsa44Roundtrip(): void
    {
        $keys = MlDsa::keyGen(44);
        $message = 'Hello, ML-DSA-44!';

        $sig = MlDsa::sign($keys['sk'], $message, 44);
        $this->assertNotEmpty($sig, 'Signature should not be empty');

        $valid = MlDsa::verify($keys['pk'], $message, $sig, 44);
        $this->assertTrue($valid, 'ML-DSA-44: valid signature must verify');
    }

    /**
     * Test ML-DSA-65 sign/verify roundtrip.
     */
    public function testMlDsa65Roundtrip(): void
    {
        $keys = MlDsa::keyGen(65);
        $message = 'Hello, ML-DSA-65!';

        $sig = MlDsa::sign($keys['sk'], $message, 65);
        $valid = MlDsa::verify($keys['pk'], $message, $sig, 65);
        $this->assertTrue($valid, 'ML-DSA-65: valid signature must verify');
    }

    /**
     * Test ML-DSA-87 sign/verify roundtrip.
     */
    public function testMlDsa87Roundtrip(): void
    {
        $keys = MlDsa::keyGen(87);
        $message = 'Hello, ML-DSA-87!';

        $sig = MlDsa::sign($keys['sk'], $message, 87);
        $valid = MlDsa::verify($keys['pk'], $message, $sig, 87);
        $this->assertTrue($valid, 'ML-DSA-87: valid signature must verify');
    }

    /**
     * Test that wrong message fails verification.
     */
    public function testWrongMessageFails(): void
    {
        $keys = MlDsa::keyGen(44);
        $message = 'Correct message';

        $sig = MlDsa::sign($keys['sk'], $message, 44);

        $valid = MlDsa::verify($keys['pk'], 'Wrong message', $sig, 44);
        $this->assertFalse($valid, 'Wrong message should fail verification');
    }

    /**
     * Test that corrupted signature fails.
     */
    public function testCorruptedSigFails(): void
    {
        $keys = MlDsa::keyGen(44);
        $message = 'Test message';

        $sig = MlDsa::sign($keys['sk'], $message, 44);

        // Corrupt signature
        $badSig = $sig;
        $badSig[10] = chr((ord($badSig[10]) + 1) & 0xFF);

        $valid = MlDsa::verify($keys['pk'], $message, $badSig, 44);
        $this->assertFalse($valid, 'Corrupted signature should fail verification');
    }
}

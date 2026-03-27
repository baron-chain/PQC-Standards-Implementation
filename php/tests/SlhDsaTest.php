<?php

declare(strict_types=1);

namespace PQC\Tests;

use PHPUnit\Framework\TestCase;
use PQC\SlhDsa\SlhParams;
use PQC\SlhDsa\SlhDsa;
use PQC\SlhDsa\Address;

class SlhDsaTest extends TestCase
{
    /**
     * Test parameters are well-formed.
     */
    public function testParams(): void
    {
        $p = SlhParams::get('shake-128f');
        $this->assertSame(16, $p['n']);
        $this->assertSame(33, $p['k']);
        $this->assertSame(6, $p['a']);
        $this->assertSame(11, $p['layers']);
        $this->assertSame(6, $p['tree_height']);
    }

    /**
     * Test Address structure.
     */
    public function testAddress(): void
    {
        $adrs = new Address();
        $adrs->setLayerAddress(3);
        $adrs->setTreeAddress(42);
        $adrs->setType(Address::WOTS_HASH);
        $adrs->setKeyPairAddress(7);

        $this->assertSame(32, strlen($adrs->toBytes()));
        $this->assertSame(7, $adrs->getKeyPairAddress());
    }

    /**
     * Test SLH-DSA-SHAKE-128f sign/verify roundtrip.
     * Note: SLH-DSA is slow, so we test with small messages.
     */
    public function testSlhDsaShake128fRoundtrip(): void
    {
        $variant = 'shake-128f';

        $keys = SlhDsa::keyGen($variant);

        $this->assertSame(SlhParams::pkSize($variant), strlen($keys['pk']),
            'Public key size mismatch');
        $this->assertSame(SlhParams::skSize($variant), strlen($keys['sk']),
            'Secret key size mismatch');

        $message = 'Hello, SLH-DSA!';
        $sig = SlhDsa::sign($keys['sk'], $message, $variant);

        $this->assertSame(SlhParams::sigSize($variant), strlen($sig),
            'Signature size mismatch');

        $valid = SlhDsa::verify($keys['pk'], $message, $sig, $variant);
        $this->assertTrue($valid, 'SLH-DSA-SHAKE-128f: valid signature must verify');
    }

    /**
     * Test that wrong message fails.
     */
    public function testSlhDsaWrongMessage(): void
    {
        $variant = 'shake-128f';

        $keys = SlhDsa::keyGen($variant);
        $sig = SlhDsa::sign($keys['sk'], 'correct', $variant);

        $valid = SlhDsa::verify($keys['pk'], 'wrong', $sig, $variant);
        $this->assertFalse($valid, 'Wrong message should fail verification');
    }
}

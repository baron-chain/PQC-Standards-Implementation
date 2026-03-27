<?php

declare(strict_types=1);

namespace PQC\Tests;

use PHPUnit\Framework\TestCase;
use PQC\Composite\CompositeSig;

class CompositeTest extends TestCase
{
    /**
     * Test Composite Signature with ML-DSA-44 + Ed25519 roundtrip.
     */
    public function testCompositeSigEd25519Roundtrip(): void
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('Sodium extension required for Ed25519');
        }

        $keys = CompositeSig::keyGen(44, 'ed25519');

        $message = 'Hello, Composite Signatures!';

        $sig = CompositeSig::sign(
            $keys['sk'],
            $message,
            44,
            'ed25519',
            $keys['mldsaSkLen']
        );

        $this->assertNotEmpty($sig, 'Composite signature should not be empty');

        $valid = CompositeSig::verify(
            $keys['pk'],
            $message,
            $sig,
            44,
            'ed25519',
            $keys['mldsaPkLen']
        );

        $this->assertTrue($valid, 'Composite: valid signature must verify');
    }

    /**
     * Test wrong message fails.
     */
    public function testCompositeSigWrongMessage(): void
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('Sodium extension required for Ed25519');
        }

        $keys = CompositeSig::keyGen(44, 'ed25519');
        $message = 'Correct message';

        $sig = CompositeSig::sign(
            $keys['sk'],
            $message,
            44,
            'ed25519',
            $keys['mldsaSkLen']
        );

        $valid = CompositeSig::verify(
            $keys['pk'],
            'Wrong message',
            $sig,
            44,
            'ed25519',
            $keys['mldsaPkLen']
        );

        $this->assertFalse($valid, 'Composite: wrong message should fail');
    }
}

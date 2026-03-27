<?php

declare(strict_types=1);

namespace PQC\Tests;

use PHPUnit\Framework\TestCase;
use PQC\Tls\NamedGroups;
use PQC\Tls\SigAlgorithms;
use PQC\Tls\CipherSuites;

class TlsTest extends TestCase
{
    /**
     * Test named groups registration.
     */
    public function testNamedGroups(): void
    {
        $all = NamedGroups::all();
        $this->assertNotEmpty($all, 'Named groups should not be empty');

        // Check specific groups exist
        $mlkem768 = NamedGroups::get(NamedGroups::MLKEM768);
        $this->assertNotNull($mlkem768);
        $this->assertSame('MLKEM768', $mlkem768['name']);
        $this->assertTrue($mlkem768['pqc']);
        $this->assertFalse($mlkem768['hybrid']);

        // Check hybrid group
        $hybrid = NamedGroups::get(NamedGroups::X25519_MLKEM768);
        $this->assertNotNull($hybrid);
        $this->assertTrue($hybrid['pqc']);
        $this->assertTrue($hybrid['hybrid']);
    }

    /**
     * Test isPqc.
     */
    public function testIsPqc(): void
    {
        $this->assertTrue(NamedGroups::isPqc(NamedGroups::MLKEM768));
        $this->assertTrue(NamedGroups::isPqc(NamedGroups::X25519_MLKEM768));
        $this->assertFalse(NamedGroups::isPqc(NamedGroups::X25519)); // Classical
    }

    /**
     * Test isHybrid.
     */
    public function testIsHybrid(): void
    {
        $this->assertFalse(NamedGroups::isHybrid(NamedGroups::MLKEM768));
        $this->assertTrue(NamedGroups::isHybrid(NamedGroups::X25519_MLKEM768));
    }

    /**
     * Test supported_groups encode/decode roundtrip.
     */
    public function testNamedGroupsEncodeDecode(): void
    {
        $groups = [NamedGroups::MLKEM768, NamedGroups::X25519_MLKEM768, NamedGroups::MLKEM512];
        $encoded = NamedGroups::encodeSupported($groups);
        $decoded = NamedGroups::decodeSupported($encoded);

        $this->assertSame($groups, $decoded);
    }

    /**
     * Test signature algorithms.
     */
    public function testSigAlgorithms(): void
    {
        $all = SigAlgorithms::all();
        $this->assertNotEmpty($all);

        $mldsa44 = SigAlgorithms::get(SigAlgorithms::MLDSA44);
        $this->assertNotNull($mldsa44);
        $this->assertSame('mldsa44', $mldsa44['name']);
        $this->assertSame('ml-dsa', $mldsa44['family']);

        $this->assertTrue(SigAlgorithms::isPqc(SigAlgorithms::MLDSA44));
        $this->assertTrue(SigAlgorithms::isPqc(SigAlgorithms::MLDSA44_ED25519));
    }

    /**
     * Test sig algorithms encode/decode.
     */
    public function testSigAlgorithmsEncodeDecode(): void
    {
        $algos = [SigAlgorithms::MLDSA44, SigAlgorithms::MLDSA65, SigAlgorithms::SLHDSA_SHAKE_128F];
        $encoded = SigAlgorithms::encodeSupported($algos);
        $decoded = SigAlgorithms::decodeSupported($encoded);

        $this->assertSame($algos, $decoded);
    }

    /**
     * Test cipher suites.
     */
    public function testCipherSuites(): void
    {
        $all = CipherSuites::all();
        $this->assertNotEmpty($all);

        $aes256 = CipherSuites::get(CipherSuites::TLS_AES_256_GCM_SHA384);
        $this->assertNotNull($aes256);
        $this->assertSame('TLS_AES_256_GCM_SHA384', $aes256['name']);
        $this->assertTrue($aes256['pqcCompatible']);

        $recommended = CipherSuites::recommended();
        $this->assertContains(CipherSuites::TLS_AES_256_GCM_SHA384, $recommended);
    }

    /**
     * Test cipher suites encode/decode.
     */
    public function testCipherSuitesEncodeDecode(): void
    {
        $suites = CipherSuites::recommended();
        $encoded = CipherSuites::encode($suites);
        $decoded = CipherSuites::decode($encoded);

        $this->assertSame($suites, $decoded);
    }

    /**
     * Test all named groups have valid structure.
     */
    public function testAllNamedGroupsValid(): void
    {
        foreach (NamedGroups::all() as $code => $info) {
            $this->assertArrayHasKey('name', $info, "Group $code missing name");
            $this->assertArrayHasKey('type', $info, "Group $code missing type");
            $this->assertArrayHasKey('pqc', $info, "Group $code missing pqc");
        }
    }

    /**
     * Test all sig algorithms have valid structure.
     */
    public function testAllSigAlgorithmsValid(): void
    {
        foreach (SigAlgorithms::all() as $code => $info) {
            $this->assertArrayHasKey('name', $info, "Algo $code missing name");
            $this->assertArrayHasKey('type', $info, "Algo $code missing type");
            $this->assertArrayHasKey('family', $info, "Algo $code missing family");
        }
    }
}

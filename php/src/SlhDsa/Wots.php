<?php

declare(strict_types=1);

namespace PQC\SlhDsa;

/**
 * WOTS+ one-time signature scheme for SLH-DSA.
 * FIPS 205 Section 5.
 */
final class Wots
{
    /**
     * Chaining function: iterate F hash `steps` times.
     */
    public static function chain(string $x, int $start, int $steps, string $pkSeed, Address $adrs, int $n): string
    {
        $tmp = $x;
        for ($i = $start; $i < $start + $steps; $i++) {
            $adrs->setHashAddress($i);
            $tmp = SlhHash::F($pkSeed, $adrs, $tmp, $n);
        }
        return $tmp;
    }

    /**
     * Generate WOTS+ public key.
     * FIPS 205 Algorithm 4.
     */
    public static function pkGen(string $skSeed, string $pkSeed, Address $adrs, array $params): string
    {
        $n = $params['n'];
        $w = $params['w'];
        $len = $params['len'];

        $wotsPkAdrs = $adrs->copy();
        $wotsPkAdrs->setType(Address::WOTS_PK);
        $wotsPkAdrs->setKeyPairAddress($adrs->getKeyPairAddress());

        $tmp = '';
        for ($i = 0; $i < $len; $i++) {
            $skAdrs = $adrs->copy();
            $skAdrs->setType(Address::WOTS_PRF);
            $skAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
            $skAdrs->setChainAddress($i);
            $skAdrs->setHashAddress(0);

            $sk = SlhHash::prf($pkSeed, $skSeed, $skAdrs, $n);

            $chainAdrs = $adrs->copy();
            $chainAdrs->setType(Address::WOTS_HASH);
            $chainAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
            $chainAdrs->setChainAddress($i);

            $tmp .= self::chain($sk, 0, $w - 1, $pkSeed, $chainAdrs, $n);
        }

        return SlhHash::Tl($pkSeed, $wotsPkAdrs, $tmp, $n);
    }

    /**
     * Generate WOTS+ signature.
     * FIPS 205 Algorithm 5.
     */
    public static function sign(string $msg, string $skSeed, string $pkSeed, Address $adrs, array $params): string
    {
        $n = $params['n'];
        $w = $params['w'];
        $len1 = $params['len1'];
        $len2 = $params['len2'];
        $len = $params['len'];
        $lgw = $params['lg_w'];

        // Convert message to base-w
        $msgBaseW = self::baseW($msg, $lgw, $len1);

        // Compute checksum
        $csum = 0;
        foreach ($msgBaseW as $v) {
            $csum += ($w - 1) - $v;
        }
        $csum <<= (8 - (($len2 * $lgw) % 8)) % 8;

        // Encode checksum in base-w
        $csumBytes = '';
        $csumLen = intdiv($len2 * $lgw + 7, 8);
        for ($i = $csumLen - 1; $i >= 0; $i--) {
            $csumBytes = chr(($csum >> ($i * 8)) & 0xFF) . $csumBytes;
        }
        // Reverse for big-endian
        $csumBytes = pack('N', $csum); // Use 4 bytes
        $csumBaseW = self::baseW($csumBytes, $lgw, $len2);

        $msgAll = array_merge($msgBaseW, $csumBaseW);

        $sig = '';
        for ($i = 0; $i < $len; $i++) {
            $skAdrs = $adrs->copy();
            $skAdrs->setType(Address::WOTS_PRF);
            $skAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
            $skAdrs->setChainAddress($i);
            $skAdrs->setHashAddress(0);

            $sk = SlhHash::prf($pkSeed, $skSeed, $skAdrs, $n);

            $chainAdrs = $adrs->copy();
            $chainAdrs->setType(Address::WOTS_HASH);
            $chainAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
            $chainAdrs->setChainAddress($i);

            $sig .= self::chain($sk, 0, $msgAll[$i], $pkSeed, $chainAdrs, $n);
        }

        return $sig;
    }

    /**
     * Compute WOTS+ public key from signature.
     * FIPS 205 Algorithm 6.
     */
    public static function pkFromSig(string $sig, string $msg, string $pkSeed, Address $adrs, array $params): string
    {
        $n = $params['n'];
        $w = $params['w'];
        $len1 = $params['len1'];
        $len2 = $params['len2'];
        $len = $params['len'];
        $lgw = $params['lg_w'];

        // Convert message to base-w
        $msgBaseW = self::baseW($msg, $lgw, $len1);

        // Compute checksum
        $csum = 0;
        foreach ($msgBaseW as $v) {
            $csum += ($w - 1) - $v;
        }
        $csum <<= (8 - (($len2 * $lgw) % 8)) % 8;

        $csumBytes = pack('N', $csum);
        $csumBaseW = self::baseW($csumBytes, $lgw, $len2);

        $msgAll = array_merge($msgBaseW, $csumBaseW);

        $wotsPkAdrs = $adrs->copy();
        $wotsPkAdrs->setType(Address::WOTS_PK);
        $wotsPkAdrs->setKeyPairAddress($adrs->getKeyPairAddress());

        $tmp = '';
        for ($i = 0; $i < $len; $i++) {
            $chainAdrs = $adrs->copy();
            $chainAdrs->setType(Address::WOTS_HASH);
            $chainAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
            $chainAdrs->setChainAddress($i);

            $sigI = substr($sig, $i * $n, $n);
            $tmp .= self::chain($sigI, $msgAll[$i], $w - 1 - $msgAll[$i], $pkSeed, $chainAdrs, $n);
        }

        return SlhHash::Tl($pkSeed, $wotsPkAdrs, $tmp, $n);
    }

    /**
     * Convert bytes to base-w representation.
     */
    private static function baseW(string $x, int $lgw, int $outLen): array
    {
        $result = [];
        $bits = 0;
        $buffer = 0;
        $pos = 0;

        for ($i = 0; $i < $outLen; $i++) {
            while ($bits < $lgw) {
                if ($pos < strlen($x)) {
                    $buffer = ($buffer << 8) | ord($x[$pos++]);
                    $bits += 8;
                } else {
                    $buffer <<= 8;
                    $bits += 8;
                }
            }
            $bits -= $lgw;
            $result[] = ($buffer >> $bits) & ((1 << $lgw) - 1);
        }

        return $result;
    }
}

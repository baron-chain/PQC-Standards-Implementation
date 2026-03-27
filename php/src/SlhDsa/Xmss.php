<?php

declare(strict_types=1);

namespace PQC\SlhDsa;

/**
 * XMSS (eXtended Merkle Signature Scheme) for SLH-DSA.
 * FIPS 205 Section 6.
 */
final class Xmss
{
    /**
     * Compute XMSS public key (root of Merkle tree).
     * FIPS 205 Algorithm 8.
     */
    public static function node(
        string $skSeed,
        string $pkSeed,
        int $targetNode,
        int $targetHeight,
        Address $adrs,
        array $params
    ): string {
        $n = $params['n'];
        $hPrime = $params['tree_height'];

        if ($targetHeight === 0) {
            // Leaf node: WOTS+ public key
            $adrs->setType(Address::WOTS_HASH);
            $adrs->setKeyPairAddress($targetNode);
            return Wots::pkGen($skSeed, $pkSeed, $adrs, $params);
        }

        $lNode = self::node($skSeed, $pkSeed, 2 * $targetNode, $targetHeight - 1, $adrs, $params);
        $rNode = self::node($skSeed, $pkSeed, 2 * $targetNode + 1, $targetHeight - 1, $adrs, $params);

        $adrs->setType(Address::TREE);
        $adrs->setTreeHeight($targetHeight);
        $adrs->setTreeIndex($targetNode);

        return SlhHash::H($pkSeed, $adrs, $lNode . $rNode, $n);
    }

    /**
     * Generate XMSS signature.
     * FIPS 205 Algorithm 9.
     *
     * @param string $msg Message (n bytes)
     * @param string $skSeed Secret seed
     * @param string $pkSeed Public seed
     * @param int $idx Leaf index to sign with
     * @param Address $adrs Address
     * @param array $params Parameters
     * @return string WOTS+ signature || authentication path
     */
    public static function sign(
        string $msg,
        string $skSeed,
        string $pkSeed,
        int $idx,
        Address $adrs,
        array $params
    ): string {
        $n = $params['n'];
        $hPrime = $params['tree_height'];

        // Generate WOTS+ signature
        $adrs->setType(Address::WOTS_HASH);
        $adrs->setKeyPairAddress($idx);
        $sig = Wots::sign($msg, $skSeed, $pkSeed, $adrs, $params);

        // Compute authentication path
        $auth = '';
        for ($j = 0; $j < $hPrime; $j++) {
            $s = ($idx >> $j) ^ 1; // Sibling index
            $auth .= self::node($skSeed, $pkSeed, $s, $j, $adrs, $params);
        }

        return $sig . $auth;
    }

    /**
     * Compute XMSS root from signature.
     * FIPS 205 Algorithm 10.
     */
    public static function rootFromSig(
        string $msg,
        string $xmssSig,
        string $pkSeed,
        int $idx,
        Address $adrs,
        array $params
    ): string {
        $n = $params['n'];
        $hPrime = $params['tree_height'];
        $len = $params['len'];

        // Extract WOTS+ signature and auth path
        $wotsSig = substr($xmssSig, 0, $len * $n);
        $auth = substr($xmssSig, $len * $n);

        // Compute WOTS+ public key from signature
        $adrs->setType(Address::WOTS_HASH);
        $adrs->setKeyPairAddress($idx);
        $node = Wots::pkFromSig($wotsSig, $msg, $pkSeed, $adrs, $params);

        // Climb the tree
        for ($j = 0; $j < $hPrime; $j++) {
            $adrs->setType(Address::TREE);
            $adrs->setTreeHeight($j + 1);

            $authJ = substr($auth, $j * $n, $n);

            if ((($idx >> $j) & 1) === 0) {
                $adrs->setTreeIndex(($idx >> ($j + 1)));
                $node = SlhHash::H($pkSeed, $adrs, $node . $authJ, $n);
            } else {
                $adrs->setTreeIndex(($idx >> ($j + 1)));
                $node = SlhHash::H($pkSeed, $adrs, $authJ . $node, $n);
            }
        }

        return $node;
    }
}

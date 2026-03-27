<?php

declare(strict_types=1);

namespace PQC\SlhDsa;

/**
 * Hypertree for SLH-DSA.
 * FIPS 205 Section 7.
 */
final class Hypertree
{
    /**
     * Generate hypertree signature.
     * FIPS 205 Algorithm 11.
     *
     * @param string $msg Message (n bytes - typically FORS pk)
     * @param string $skSeed Secret seed
     * @param string $pkSeed Public seed
     * @param int $idxTree Tree index
     * @param int $idxLeaf Leaf index in bottom tree
     * @param array $params Parameters
     * @return string Hypertree signature
     */
    public static function sign(
        string $msg,
        string $skSeed,
        string $pkSeed,
        int $idxTree,
        int $idxLeaf,
        array $params
    ): string {
        $d = $params['layers'];
        $hPrime = $params['tree_height'];
        $n = $params['n'];

        $adrs = new Address();

        // Sign at the bottom layer
        $adrs->setLayerAddress(0);
        $adrs->setTreeAddress($idxTree);

        $sig = Xmss::sign($msg, $skSeed, $pkSeed, $idxLeaf, $adrs, $params);
        $root = Xmss::rootFromSig($msg, $sig, $pkSeed, $idxLeaf, $adrs, $params);

        // Sign at each subsequent layer
        for ($j = 1; $j < $d; $j++) {
            $idxLeaf = $idxTree & ((1 << $hPrime) - 1);
            $idxTree >>= $hPrime;

            $adrs->setLayerAddress($j);
            $adrs->setTreeAddress($idxTree);

            $sig .= Xmss::sign($root, $skSeed, $pkSeed, $idxLeaf, $adrs, $params);
            if ($j < $d - 1) {
                $root = Xmss::rootFromSig($root, substr($sig, -($hPrime + $params['len']) * $n), $pkSeed, $idxLeaf, $adrs, $params);
            }
        }

        return $sig;
    }

    /**
     * Verify hypertree signature.
     * FIPS 205 Algorithm 12.
     */
    public static function verify(
        string $msg,
        string $htSig,
        string $pkSeed,
        int $idxTree,
        int $idxLeaf,
        string $pkRoot,
        array $params
    ): bool {
        $d = $params['layers'];
        $hPrime = $params['tree_height'];
        $n = $params['n'];
        $len = $params['len'];

        $adrs = new Address();
        $xmssSigSize = ($hPrime + $len) * $n;

        // Verify at the bottom layer
        $adrs->setLayerAddress(0);
        $adrs->setTreeAddress($idxTree);

        $xmssSig = substr($htSig, 0, $xmssSigSize);
        $node = Xmss::rootFromSig($msg, $xmssSig, $pkSeed, $idxLeaf, $adrs, $params);

        // Verify each subsequent layer
        for ($j = 1; $j < $d; $j++) {
            $idxLeaf = $idxTree & ((1 << $hPrime) - 1);
            $idxTree >>= $hPrime;

            $adrs->setLayerAddress($j);
            $adrs->setTreeAddress($idxTree);

            $xmssSig = substr($htSig, $j * $xmssSigSize, $xmssSigSize);
            $node = Xmss::rootFromSig($node, $xmssSig, $pkSeed, $idxLeaf, $adrs, $params);
        }

        return hash_equals($node, $pkRoot);
    }
}

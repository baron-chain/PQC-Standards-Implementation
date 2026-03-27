<?php

declare(strict_types=1);

namespace PQC\SlhDsa;

/**
 * FORS (Forest of Random Subsets) for SLH-DSA.
 * FIPS 205 Section 8.
 */
final class Fors
{
    /**
     * Generate a FORS private key value.
     */
    private static function skGen(string $skSeed, string $pkSeed, Address $adrs, int $idx, int $n): string
    {
        $skAdrs = $adrs->copy();
        $skAdrs->setType(Address::FORS_PRF);
        $skAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
        $skAdrs->setTreeIndex($idx);
        $skAdrs->setTreeHeight(0);

        return SlhHash::prf($pkSeed, $skSeed, $skAdrs, $n);
    }

    /**
     * Compute a node in a FORS tree.
     */
    private static function treeNode(
        string $skSeed,
        string $pkSeed,
        int $targetNode,
        int $targetHeight,
        Address $adrs,
        int $treeIdx,
        int $n
    ): string {
        if ($targetHeight === 0) {
            $sk = self::skGen($skSeed, $pkSeed, $adrs, $treeIdx * (1 << 0) + $targetNode, $n);
            $leafAdrs = $adrs->copy();
            $leafAdrs->setType(Address::FORS_TREE);
            $leafAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
            $leafAdrs->setTreeHeight(0);
            $leafAdrs->setTreeIndex($treeIdx * 1 + $targetNode);

            return SlhHash::F($pkSeed, $leafAdrs, $sk, $n);
        }

        $lNode = self::treeNode($skSeed, $pkSeed, 2 * $targetNode, $targetHeight - 1, $adrs, $treeIdx, $n);
        $rNode = self::treeNode($skSeed, $pkSeed, 2 * $targetNode + 1, $targetHeight - 1, $adrs, $treeIdx, $n);

        $nodeAdrs = $adrs->copy();
        $nodeAdrs->setType(Address::FORS_TREE);
        $nodeAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
        $nodeAdrs->setTreeHeight($targetHeight);
        $nodeAdrs->setTreeIndex($treeIdx * (1 << $targetHeight) + $targetNode);

        return SlhHash::H($pkSeed, $nodeAdrs, $lNode . $rNode, $n);
    }

    /**
     * Generate FORS signature.
     * FIPS 205 Algorithm 14.
     *
     * @param string $md Message digest
     * @param string $skSeed Secret seed
     * @param string $pkSeed Public seed
     * @param Address $adrs Address
     * @param array $params Parameters
     * @return string FORS signature
     */
    public static function sign(
        string $md,
        string $skSeed,
        string $pkSeed,
        Address $adrs,
        array $params
    ): string {
        $n = $params['n'];
        $k = $params['k'];
        $a = $params['a'];

        // Split md into k indices of a bits each
        $indices = self::messageToIndices($md, $k, $a);

        $sig = '';
        for ($i = 0; $i < $k; $i++) {
            $idx = $indices[$i];

            // Secret value
            $sig .= self::skGen($skSeed, $pkSeed, $adrs, $i * (1 << $a) + $idx, $n);

            // Authentication path
            for ($j = 0; $j < $a; $j++) {
                $s = ($idx >> $j) ^ 1;
                $sig .= self::treeNode($skSeed, $pkSeed, $s, $j, $adrs, $i, $n);
            }
        }

        return $sig;
    }

    /**
     * Compute FORS public key from signature.
     * FIPS 205 Algorithm 15.
     */
    public static function pkFromSig(
        string $sig,
        string $md,
        string $pkSeed,
        Address $adrs,
        array $params
    ): string {
        $n = $params['n'];
        $k = $params['k'];
        $a = $params['a'];

        $indices = self::messageToIndices($md, $k, $a);

        $roots = '';
        $offset = 0;

        for ($i = 0; $i < $k; $i++) {
            $idx = $indices[$i];

            // Get sk value from sig
            $sk = substr($sig, $offset, $n);
            $offset += $n;

            // Compute leaf
            $leafAdrs = $adrs->copy();
            $leafAdrs->setType(Address::FORS_TREE);
            $leafAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
            $leafAdrs->setTreeHeight(0);
            $leafAdrs->setTreeIndex($i * (1 << $a) + $idx);

            $node = SlhHash::F($pkSeed, $leafAdrs, $sk, $n);

            // Climb the tree
            for ($j = 0; $j < $a; $j++) {
                $authJ = substr($sig, $offset, $n);
                $offset += $n;

                $nodeAdrs = $adrs->copy();
                $nodeAdrs->setType(Address::FORS_TREE);
                $nodeAdrs->setKeyPairAddress($adrs->getKeyPairAddress());
                $nodeAdrs->setTreeHeight($j + 1);

                if ((($idx >> $j) & 1) === 0) {
                    $nodeAdrs->setTreeIndex($i * (1 << ($j + 1)) + ($idx >> ($j + 1)));
                    $node = SlhHash::H($pkSeed, $nodeAdrs, $node . $authJ, $n);
                } else {
                    $nodeAdrs->setTreeIndex($i * (1 << ($j + 1)) + ($idx >> ($j + 1)));
                    $node = SlhHash::H($pkSeed, $nodeAdrs, $authJ . $node, $n);
                }
            }

            $roots .= $node;
        }

        // Compress FORS roots into single public key
        $forsRootAdrs = $adrs->copy();
        $forsRootAdrs->setType(Address::FORS_ROOTS);
        $forsRootAdrs->setKeyPairAddress($adrs->getKeyPairAddress());

        return SlhHash::Tl($pkSeed, $forsRootAdrs, $roots, $n);
    }

    /**
     * Split message digest into k indices of a bits each.
     */
    private static function messageToIndices(string $md, int $k, int $a): array
    {
        $indices = [];
        $bits = 0;
        $buffer = 0;
        $pos = 0;

        for ($i = 0; $i < $k; $i++) {
            while ($bits < $a) {
                if ($pos < strlen($md)) {
                    $buffer = ($buffer << 8) | ord($md[$pos++]);
                    $bits += 8;
                } else {
                    $buffer <<= 8;
                    $bits += 8;
                }
            }
            $bits -= $a;
            $indices[] = ($buffer >> $bits) & ((1 << $a) - 1);
        }

        return $indices;
    }
}

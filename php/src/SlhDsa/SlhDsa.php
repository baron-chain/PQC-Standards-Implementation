<?php

declare(strict_types=1);

namespace PQC\SlhDsa;

/**
 * SLH-DSA: Stateless Hash-Based Digital Signature Algorithm.
 * FIPS 205.
 */
final class SlhDsa
{
    /**
     * Generate key pair.
     *
     * @param string $variant e.g., 'shake-128f'
     * @return array{pk: string, sk: string}
     */
    public static function keyGen(string $variant): array
    {
        $params = SlhParams::get($variant);
        $n = $params['n'];

        $skSeed = random_bytes($n);
        $skPrf = random_bytes($n);
        $pkSeed = random_bytes($n);

        return self::keyGenInternal($skSeed, $skPrf, $pkSeed, $variant);
    }

    /**
     * Internal deterministic key generation.
     */
    public static function keyGenInternal(string $skSeed, string $skPrf, string $pkSeed, string $variant): array
    {
        $params = SlhParams::get($variant);
        $n = $params['n'];
        $hPrime = $params['tree_height'];

        $adrs = new Address();
        $adrs->setLayerAddress($params['layers'] - 1);
        $adrs->setTreeAddress(0);

        // Compute the root of the top XMSS tree
        $pkRoot = Xmss::node($skSeed, $pkSeed, 0, $hPrime, $adrs, $params);

        $pk = $pkSeed . $pkRoot;
        $sk = $skSeed . $skPrf . $pkSeed . $pkRoot;

        return ['pk' => $pk, 'sk' => $sk];
    }

    /**
     * Sign a message.
     *
     * @param string $sk Secret key
     * @param string $message Message
     * @param string $variant e.g., 'shake-128f'
     * @return string Signature
     */
    public static function sign(string $sk, string $message, string $variant): string
    {
        $params = SlhParams::get($variant);
        $n = $params['n'];
        $k = $params['k'];
        $a = $params['a'];
        $hPrime = $params['tree_height'];
        $d = $params['layers'];
        $mdLen = $params['mdLen'];

        // Parse secret key
        $skSeed = substr($sk, 0, $n);
        $skPrf = substr($sk, $n, $n);
        $pkSeed = substr($sk, 2 * $n, $n);
        $pkRoot = substr($sk, 3 * $n, $n);

        // Randomize
        $optRand = random_bytes($n);

        return self::signInternal($skSeed, $skPrf, $pkSeed, $pkRoot, $message, $optRand, $variant);
    }

    /**
     * Internal deterministic signing.
     */
    public static function signInternal(
        string $skSeed,
        string $skPrf,
        string $pkSeed,
        string $pkRoot,
        string $message,
        string $optRand,
        string $variant
    ): string {
        $params = SlhParams::get($variant);
        $n = $params['n'];
        $k = $params['k'];
        $a = $params['a'];
        $hPrime = $params['tree_height'];
        $d = $params['layers'];
        $mdLen = $params['mdLen'];

        // R = PRF_msg(SK.prf, optRand, M)
        $R = SlhHash::prfMsg($skPrf, $optRand, $message, $n);

        $treeIdxLen = $params['treeIdxLen'];
        $leafIdxLen = $params['leafIdxLen'];
        $totalDigestLen = $mdLen; // mdLen already includes treeIdxLen + leafIdxLen

        // digest = H_msg(R, PK.seed, PK.root, M) — output length = mdLen
        $digest = SlhHash::hMsg($R, $pkSeed, $pkRoot, $message, $totalDigestLen);

        // Split digest into md, idx_tree, idx_leaf
        $mdBits = $k * $a;
        $mdBytes = intdiv($mdBits + 7, 8);
        $md = substr($digest, 0, $mdBytes);

        $idxTree = 0;
        $idxLeaf = 0;

        // Extract idxTree (treeIdxLen bytes, big-endian)
        for ($i = 0; $i < $treeIdxLen; $i++) {
            $idxTree = ($idxTree << 8) | ord($digest[$mdBytes + $i]);
        }
        $treeBits = $params['full_height'] - $hPrime;
        if ($treeBits < 63) {
            $idxTree &= (1 << $treeBits) - 1;
        } elseif ($treeBits === 63) {
            $idxTree &= PHP_INT_MAX;  // (1<<63)-1 overflows in PHP
        }
        // treeBits >= 64: no masking needed

        // Extract idxLeaf (leafIdxLen bytes, big-endian)
        for ($i = 0; $i < $leafIdxLen; $i++) {
            $idxLeaf = ($idxLeaf << 8) | ord($digest[$mdBytes + $treeIdxLen + $i]);
        }
        $idxLeaf &= (1 << $hPrime) - 1;

        // FORS sign
        $forsAdrs = new Address();
        $forsAdrs->setLayerAddress(0);
        $forsAdrs->setTreeAddress($idxTree);
        $forsAdrs->setType(Address::FORS_TREE);
        $forsAdrs->setKeyPairAddress($idxLeaf);

        $forsSig = Fors::sign($md, $skSeed, $pkSeed, $forsAdrs, $params);
        $forsPk = Fors::pkFromSig($forsSig, $md, $pkSeed, $forsAdrs, $params);

        // Hypertree sign
        $htSig = Hypertree::sign($forsPk, $skSeed, $pkSeed, $idxTree, $idxLeaf, $params);

        return $R . $forsSig . $htSig;
    }

    /**
     * Verify a signature.
     */
    public static function verify(string $pk, string $message, string $sig, string $variant): bool
    {
        $params = SlhParams::get($variant);
        $n = $params['n'];
        $k = $params['k'];
        $a = $params['a'];
        $hPrime = $params['tree_height'];
        $d = $params['layers'];
        $mdLen = $params['mdLen'];

        // Parse public key
        $pkSeed = substr($pk, 0, $n);
        $pkRoot = substr($pk, $n, $n);

        // Parse signature
        $R = substr($sig, 0, $n);
        $offset = $n;

        $forsSigSize = $k * ($a + 1) * $n;
        $forsSig = substr($sig, $offset, $forsSigSize);
        $offset += $forsSigSize;

        $htSig = substr($sig, $offset);

        $treeIdxLen = $params['treeIdxLen'];
        $leafIdxLen = $params['leafIdxLen'];

        // Compute digest (full length = mdLen)
        $digest = SlhHash::hMsg($R, $pkSeed, $pkRoot, $message, $mdLen);

        // Split digest
        $mdBits = $k * $a;
        $mdBytes = intdiv($mdBits + 7, 8);
        $md = substr($digest, 0, $mdBytes);

        $idxTree = 0;
        $idxLeaf = 0;

        // Extract idxTree (treeIdxLen bytes, big-endian)
        for ($i = 0; $i < $treeIdxLen; $i++) {
            $idxTree = ($idxTree << 8) | ord($digest[$mdBytes + $i]);
        }
        $treeBits = $params['full_height'] - $hPrime;
        if ($treeBits < 63) {
            $idxTree &= (1 << $treeBits) - 1;
        } elseif ($treeBits === 63) {
            $idxTree &= PHP_INT_MAX;  // (1<<63)-1 overflows in PHP
        }
        // treeBits >= 64: no masking needed

        // Extract idxLeaf (leafIdxLen bytes, big-endian)
        for ($i = 0; $i < $leafIdxLen; $i++) {
            $idxLeaf = ($idxLeaf << 8) | ord($digest[$mdBytes + $treeIdxLen + $i]);
        }
        $idxLeaf &= (1 << $hPrime) - 1;

        // FORS verify
        $forsAdrs = new Address();
        $forsAdrs->setLayerAddress(0);
        $forsAdrs->setTreeAddress($idxTree);
        $forsAdrs->setType(Address::FORS_TREE);
        $forsAdrs->setKeyPairAddress($idxLeaf);

        $forsPk = Fors::pkFromSig($forsSig, $md, $pkSeed, $forsAdrs, $params);

        // Hypertree verify
        return Hypertree::verify($forsPk, $htSig, $pkSeed, $idxTree, $idxLeaf, $pkRoot, $params);
    }
}

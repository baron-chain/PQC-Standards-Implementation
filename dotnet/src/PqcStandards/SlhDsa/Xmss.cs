namespace PqcStandards.SlhDsa;

/// <summary>XMSS tree operations for SLH-DSA.</summary>
public static class Xmss
{
    /// <summary>Compute a node in the XMSS tree.</summary>
    public static byte[] Node(IHashSuite hash, byte[] pkSeed, byte[] skSeed, int idx, int height, Address adrs, SlhParams p)
    {
        if (height == 0)
        {
            // Leaf: WOTS+ public key
            adrs.SetType(Address.WotsHash);
            adrs.SetKeyPairAddress(idx);
            return Wots.PkGen(hash, pkSeed, skSeed, adrs, p);
        }

        byte[] left = Node(hash, pkSeed, skSeed, 2 * idx, height - 1, adrs, p);
        byte[] right = Node(hash, pkSeed, skSeed, 2 * idx + 1, height - 1, adrs, p);

        adrs.SetType(Address.TreeNode);
        adrs.SetTreeHeight(height);
        adrs.SetTreeIndex(idx);
        return hash.H(pkSeed, adrs, left, right, p.N);
    }

    /// <summary>XMSS signature: (WOTS+ sig, authentication path).</summary>
    public static (byte[][] wotsSig, byte[][] authPath) Sign(IHashSuite hash, byte[] pkSeed, byte[] skSeed, byte[] msg, int idx, Address adrs, SlhParams p)
    {
        // WOTS+ signature on msg
        adrs.SetType(Address.WotsHash);
        adrs.SetKeyPairAddress(idx);
        byte[][] wotsSig = Wots.Sign(hash, pkSeed, skSeed, msg, adrs, p);

        // Authentication path
        int hPrime = p.HPrime;
        byte[][] authPath = new byte[hPrime][];
        for (int j = 0; j < hPrime; j++)
        {
            int sibIdx = (idx >> j) ^ 1;
            authPath[j] = Node(hash, pkSeed, skSeed, sibIdx, j, adrs, p);
        }

        return (wotsSig, authPath);
    }

    /// <summary>Compute XMSS root from signature.</summary>
    public static byte[] PkFromSig(IHashSuite hash, byte[] pkSeed, byte[][] wotsSig, byte[][] authPath, byte[] msg, int idx, Address adrs, SlhParams p)
    {
        // Recover WOTS+ public key
        adrs.SetType(Address.WotsHash);
        adrs.SetKeyPairAddress(idx);
        byte[] node = Wots.PkFromSig(hash, pkSeed, wotsSig, msg, adrs, p);

        // Walk up the tree
        adrs.SetType(Address.TreeNode);
        adrs.SetTreeIndex(idx);
        for (int j = 0; j < authPath.Length; j++)
        {
            adrs.SetTreeHeight(j + 1);
            int treeIdx = idx >> j;
            if ((treeIdx & 1) == 0)
            {
                adrs.SetTreeIndex(treeIdx >> 1);
                node = hash.H(pkSeed, adrs, node, authPath[j], p.N);
            }
            else
            {
                adrs.SetTreeIndex(treeIdx >> 1);
                node = hash.H(pkSeed, adrs, authPath[j], node, p.N);
            }
        }

        return node;
    }
}

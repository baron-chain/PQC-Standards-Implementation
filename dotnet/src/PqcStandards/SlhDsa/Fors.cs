namespace PqcStandards.SlhDsa;

/// <summary>FORS (Forest of Random Subsets) for SLH-DSA.</summary>
public static class Fors
{
    /// <summary>Generate FORS secret key value (ForsPRF address type).</summary>
    public static byte[] SkGen(IHashSuite hash, byte[] pkSeed, byte[] skSeed, Address adrs, int idx, int n)
    {
        var skAdrs = adrs.Copy();
        skAdrs.SetType(Address.ForsCompress);  // ForsPRF = 6; zeroes bytes 20-31
        skAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());  // restore from original
        skAdrs.SetTreeIndex(idx);
        return hash.Prf(pkSeed, skSeed, skAdrs, n);
    }

    /// <summary>Compute node at (idx, height) in FORS tree. Does not mutate adrs.</summary>
    public static byte[] Node(IHashSuite hash, byte[] pkSeed, byte[] skSeed, int idx, int height, Address adrs, SlhParams p)
    {
        int kp = adrs.GetKeyPairAddress();
        if (height == 0)
        {
            byte[] sk = SkGen(hash, pkSeed, skSeed, adrs, idx, p.N);
            var nodeAdrs = adrs.Copy();
            nodeAdrs.SetType(Address.ForsTree);
            nodeAdrs.SetKeyPairAddress(kp);
            nodeAdrs.SetTreeHeight(0);
            nodeAdrs.SetTreeIndex(idx);
            return hash.F(pkSeed, nodeAdrs, sk, p.N);
        }

        byte[] left  = Node(hash, pkSeed, skSeed, 2 * idx,     height - 1, adrs, p);
        byte[] right = Node(hash, pkSeed, skSeed, 2 * idx + 1, height - 1, adrs, p);

        var nodeAdrs2 = adrs.Copy();
        nodeAdrs2.SetType(Address.ForsTree);
        nodeAdrs2.SetKeyPairAddress(kp);
        nodeAdrs2.SetTreeHeight(height);
        nodeAdrs2.SetTreeIndex(idx);
        return hash.H(pkSeed, nodeAdrs2, left, right, p.N);
    }

    /// <summary>FORS signature: K secret values + K authentication paths of length A.</summary>
    public static (byte[][] sks, byte[][][] authPaths) Sign(IHashSuite hash, byte[] pkSeed, byte[] skSeed, byte[] md, Address adrs, SlhParams p)
    {
        int k = p.K;  // number of FORS trees
        int a = p.A;  // FORS tree height

        int[] indices = MessageToIndices(md, k, a);

        byte[][] sks = new byte[k][];
        byte[][][] authPaths = new byte[k][][];

        for (int i = 0; i < k; i++)
        {
            int baseIdx = i * (1 << a);
            int leafIdx = indices[i];
            sks[i] = SkGen(hash, pkSeed, skSeed, adrs, baseIdx + leafIdx, p.N);

            authPaths[i] = new byte[a][];
            int s = leafIdx;
            for (int j = 0; j < a; j++)
            {
                // Global sibling index at height j: i*(1<<(a-j)) + ((idx>>j)^1)
                int globalSibling = i * (1 << (a - j)) + (s ^ 1);
                authPaths[i][j] = Node(hash, pkSeed, skSeed, globalSibling, j, adrs, p);
                s >>= 1;
            }
        }

        return (sks, authPaths);
    }

    /// <summary>Compute FORS public key from signature.</summary>
    public static byte[] PkFromSig(IHashSuite hash, byte[] pkSeed, byte[][] sks, byte[][][] authPaths, byte[] md, Address adrs, SlhParams p)
    {
        int k = p.K;  // number of FORS trees
        int a = p.A;  // FORS tree height
        int n = p.N;
        int kp = adrs.GetKeyPairAddress();

        int[] indices = MessageToIndices(md, k, a);
        byte[][] roots = new byte[k][];

        for (int i = 0; i < k; i++)
        {
            int baseIdx = i * (1 << a);
            int leafIdx = indices[i];
            int absIdx  = baseIdx + leafIdx;

            var nodeAdrs = adrs.Copy();
            nodeAdrs.SetType(Address.ForsTree);
            nodeAdrs.SetKeyPairAddress(kp);
            nodeAdrs.SetTreeHeight(0);
            nodeAdrs.SetTreeIndex(absIdx);
            byte[] node = hash.F(pkSeed, nodeAdrs, sks[i], n);

            int s = leafIdx;
            for (int j = 0; j < a; j++)
            {
                nodeAdrs.SetTreeHeight(j + 1);
                nodeAdrs.SetTreeIndex(absIdx >> (j + 1));
                if (s % 2 == 0)
                    node = hash.H(pkSeed, nodeAdrs, node, authPaths[i][j], n);
                else
                    node = hash.H(pkSeed, nodeAdrs, authPaths[i][j], node, n);
                s >>= 1;
            }
            roots[i] = node;
        }

        var forsRootsAdrs = adrs.Copy();
        forsRootsAdrs.SetType(Address.ForsPk);
        forsRootsAdrs.SetKeyPairAddress(kp);
        byte[] concat = new byte[k * n];
        for (int i = 0; i < k; i++)
            Buffer.BlockCopy(roots[i], 0, concat, i * n, n);
        return hash.Tl(pkSeed, forsRootsAdrs, concat, n);
    }

    /// <summary>Extract k indices of a bits each from md (MSB-first bit order).</summary>
    private static int[] MessageToIndices(byte[] md, int k, int a)
    {
        int[] indices = new int[k];
        int bitPos = 0;
        for (int i = 0; i < k; i++)
        {
            int val = 0;
            for (int b = 0; b < a; b++)
            {
                int byteIdx = bitPos / 8;
                int bitIdx  = 7 - (bitPos % 8);  // MSB first
                if (byteIdx < md.Length)
                    val = (val << 1) | ((md[byteIdx] >> bitIdx) & 1);
                bitPos++;
            }
            indices[i] = val;
        }
        return indices;
    }
}

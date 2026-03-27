namespace PqcStandards.SlhDsa;

/// <summary>FORS (Forest of Random Subsets) for SLH-DSA.</summary>
public static class Fors
{
    /// <summary>Generate FORS secret key value.</summary>
    public static byte[] SkGen(IHashSuite hash, byte[] pkSeed, byte[] skSeed, Address adrs, int idx, int n)
    {
        adrs.SetType(Address.ForsTree);
        adrs.SetTreeHeight(0);
        adrs.SetTreeIndex(idx);
        return hash.Prf(pkSeed, skSeed, adrs, n);
    }

    /// <summary>Compute node in FORS tree.</summary>
    public static byte[] Node(IHashSuite hash, byte[] pkSeed, byte[] skSeed, int idx, int height, Address adrs, SlhParams p)
    {
        if (height == 0)
        {
            byte[] sk = SkGen(hash, pkSeed, skSeed, adrs, idx, p.N);
            adrs.SetType(Address.ForsTree);
            adrs.SetTreeHeight(0);
            adrs.SetTreeIndex(idx);
            return hash.F(pkSeed, adrs, sk, p.N);
        }

        byte[] left = Node(hash, pkSeed, skSeed, 2 * idx, height - 1, adrs, p);
        byte[] right = Node(hash, pkSeed, skSeed, 2 * idx + 1, height - 1, adrs, p);

        adrs.SetType(Address.ForsTree);
        adrs.SetTreeHeight(height);
        adrs.SetTreeIndex(idx);
        return hash.H(pkSeed, adrs, left, right, p.N);
    }

    /// <summary>FORS signature: k secret values + k authentication paths.</summary>
    public static (byte[][] sks, byte[][][] authPaths) Sign(IHashSuite hash, byte[] pkSeed, byte[] skSeed, byte[] md, Address adrs, SlhParams p)
    {
        int k = p.A;
        int a = p.K; // log of number of leaves per tree

        int[] indices = MessageToIndices(md, k, a);

        byte[][] sks = new byte[k][];
        byte[][][] authPaths = new byte[k][][];

        for (int i = 0; i < k; i++)
        {
            int baseIdx = i * (1 << a);
            sks[i] = SkGen(hash, pkSeed, skSeed, adrs, baseIdx + indices[i], p.N);

            authPaths[i] = new byte[a][];
            for (int j = 0; j < a; j++)
            {
                int sibIdx = ((baseIdx + indices[i]) >> j) ^ 1;
                authPaths[i][j] = Node(hash, pkSeed, skSeed, sibIdx, j, adrs, p);
            }
        }

        return (sks, authPaths);
    }

    /// <summary>Compute FORS public key from signature.</summary>
    public static byte[] PkFromSig(IHashSuite hash, byte[] pkSeed, byte[][] sks, byte[][][] authPaths, byte[] md, Address adrs, SlhParams p)
    {
        int k = p.A;
        int a = p.K;
        int n = p.N;

        int[] indices = MessageToIndices(md, k, a);
        byte[][] roots = new byte[k][];

        for (int i = 0; i < k; i++)
        {
            int baseIdx = i * (1 << a);
            // Leaf from secret value
            adrs.SetType(Address.ForsTree);
            adrs.SetTreeHeight(0);
            adrs.SetTreeIndex(baseIdx + indices[i]);
            byte[] node = hash.F(pkSeed, adrs, sks[i], n);

            // Walk up tree
            int curIdx = baseIdx + indices[i];
            for (int j = 0; j < a; j++)
            {
                adrs.SetTreeHeight(j + 1);
                if ((curIdx & 1) == 0)
                {
                    adrs.SetTreeIndex(curIdx >> 1);
                    node = hash.H(pkSeed, adrs, node, authPaths[i][j], n);
                }
                else
                {
                    adrs.SetTreeIndex(curIdx >> 1);
                    node = hash.H(pkSeed, adrs, authPaths[i][j], node, n);
                }
                curIdx >>= 1;
            }
            roots[i] = node;
        }

        // Compress roots
        adrs.SetType(Address.ForsPk);
        byte[] concat = new byte[k * n];
        for (int i = 0; i < k; i++)
            Buffer.BlockCopy(roots[i], 0, concat, i * n, n);
        return hash.Tl(pkSeed, adrs, concat, n);
    }

    private static int[] MessageToIndices(byte[] md, int k, int a)
    {
        int[] indices = new int[k];
        int bitPos = 0;
        for (int i = 0; i < k; i++)
        {
            int val = 0;
            for (int b = 0; b < a; b++)
            {
                int byteIdx = (bitPos + b) / 8;
                int bitIdx = (bitPos + b) % 8;
                if (byteIdx < md.Length)
                    val |= ((md[byteIdx] >> bitIdx) & 1) << b;
            }
            indices[i] = val;
            bitPos += a;
        }
        return indices;
    }
}

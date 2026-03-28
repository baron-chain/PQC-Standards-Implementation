namespace PqcStandards.SlhDsa;

/// <summary>Hypertree operations for SLH-DSA.</summary>
public static class Hypertree
{
    /// <summary>Hypertree sign: signs a message at a given (tree, leafIdx) position across d layers.</summary>
    public static byte[] Sign(IHashSuite hash, byte[] pkSeed, byte[] skSeed, byte[] msg, long idxTree, int idxLeaf, SlhParams p)
    {
        using var sigStream = new MemoryStream();
        Address adrs = new();

        // Layer 0
        adrs.SetLayerAddress(0);
        adrs.SetTreeAddress(idxTree);
        var (wotsSig, authPath) = Xmss.Sign(hash, pkSeed, skSeed, msg, idxLeaf, adrs, p);
        WriteSigPart(sigStream, wotsSig, authPath, p.N);

        byte[] root = Xmss.PkFromSig(hash, pkSeed, wotsSig, authPath, msg, idxLeaf, adrs, p);

        // Layers 1..d-1
        for (int j = 1; j < p.D; j++)
        {
            idxLeaf = (int)(idxTree & ((1L << p.HPrime) - 1));
            idxTree >>>= p.HPrime; // unsigned right shift (avoid sign-extension for 64-bit tree indices)

            adrs.SetLayerAddress(j);
            adrs.SetTreeAddress(idxTree);
            var (ws, ap) = Xmss.Sign(hash, pkSeed, skSeed, root, idxLeaf, adrs, p);
            WriteSigPart(sigStream, ws, ap, p.N);

            root = Xmss.PkFromSig(hash, pkSeed, ws, ap, root, idxLeaf, adrs, p);
        }

        return sigStream.ToArray();
    }

    /// <summary>Hypertree verify: verify a hypertree signature.</summary>
    public static bool Verify(IHashSuite hash, byte[] pkSeed, byte[] msg, byte[] sig, long idxTree, int idxLeaf, byte[] pkRoot, SlhParams p)
    {
        int offset = 0;
        Address adrs = new();
        byte[] currentMsg = msg;

        for (int j = 0; j < p.D; j++)
        {
            adrs.SetLayerAddress(j);
            adrs.SetTreeAddress(idxTree);

            var (wotsSig, authPath) = ReadSigPart(sig, ref offset, p);
            byte[] root = Xmss.PkFromSig(hash, pkSeed, wotsSig, authPath, currentMsg, idxLeaf, adrs, p);

            currentMsg = root;
            if (j < p.D - 1)
            {
                idxLeaf = (int)(idxTree & ((1L << p.HPrime) - 1));
                idxTree >>>= p.HPrime; // unsigned right shift
            }
        }

        return currentMsg.AsSpan().SequenceEqual(pkRoot);
    }

    private static void WriteSigPart(MemoryStream ms, byte[][] wotsSig, byte[][] authPath, int n)
    {
        foreach (var s in wotsSig)
            ms.Write(s, 0, n);
        foreach (var a in authPath)
            ms.Write(a, 0, n);
    }

    private static (byte[][] wotsSig, byte[][] authPath) ReadSigPart(byte[] sig, ref int offset, SlhParams p)
    {
        int n = p.N;
        byte[][] wotsSig = new byte[p.Len][];
        for (int i = 0; i < p.Len; i++)
        {
            wotsSig[i] = new byte[n];
            Buffer.BlockCopy(sig, offset, wotsSig[i], 0, n);
            offset += n;
        }

        byte[][] authPath = new byte[p.HPrime][];
        for (int i = 0; i < p.HPrime; i++)
        {
            authPath[i] = new byte[n];
            Buffer.BlockCopy(sig, offset, authPath[i], 0, n);
            offset += n;
        }

        return (wotsSig, authPath);
    }
}

using System.Security.Cryptography;

namespace PqcStandards.SlhDsa;

/// <summary>SLH-DSA digital signature algorithm (FIPS 205).</summary>
public static class SlhDsaAlgorithm
{
    /// <summary>Create the hash suite for the given params.</summary>
    public static IHashSuite GetHashSuite(SlhParams p) =>
        p.HashFamily == "SHAKE" ? new ShakeHash() : new Sha2Hash();

    /// <summary>SLH-DSA.KeyGen: returns (pk, sk).</summary>
    public static (byte[] pk, byte[] sk) KeyGen(SlhParams p)
    {
        byte[] skSeed = RandomNumberGenerator.GetBytes(p.N);
        byte[] skPrf = RandomNumberGenerator.GetBytes(p.N);
        byte[] pkSeed = RandomNumberGenerator.GetBytes(p.N);
        return KeyGenInternal(p, skSeed, skPrf, pkSeed);
    }

    internal static (byte[] pk, byte[] sk) KeyGenInternal(SlhParams p, byte[] skSeed, byte[] skPrf, byte[] pkSeed)
    {
        var hash = GetHashSuite(p);
        Address adrs = new();
        adrs.SetLayerAddress(p.D - 1);
        byte[] pkRoot = Xmss.Node(hash, pkSeed, skSeed, 0, p.HPrime, adrs, p);

        // pk = (pkSeed || pkRoot)
        byte[] pk = new byte[2 * p.N];
        Buffer.BlockCopy(pkSeed, 0, pk, 0, p.N);
        Buffer.BlockCopy(pkRoot, 0, pk, p.N, p.N);

        // sk = (skSeed || skPrf || pkSeed || pkRoot)
        byte[] sk = new byte[4 * p.N];
        Buffer.BlockCopy(skSeed, 0, sk, 0, p.N);
        Buffer.BlockCopy(skPrf, 0, sk, p.N, p.N);
        Buffer.BlockCopy(pkSeed, 0, sk, 2 * p.N, p.N);
        Buffer.BlockCopy(pkRoot, 0, sk, 3 * p.N, p.N);

        return (pk, sk);
    }

    /// <summary>SLH-DSA.Sign: returns signature.</summary>
    public static byte[] Sign(SlhParams p, byte[] sk, byte[] message)
    {
        int n = p.N;
        byte[] skSeed = sk[..n];
        byte[] skPrf = sk[n..(2 * n)];
        byte[] pkSeed = sk[(2 * n)..(3 * n)];
        byte[] pkRoot = sk[(3 * n)..];

        var hash = GetHashSuite(p);

        // Randomized: opt_rand = random N bytes
        byte[] optRand = RandomNumberGenerator.GetBytes(n);

        // R = PRF_msg(sk_prf, opt_rand, M)
        byte[] R = hash.PrfMsg(skPrf, optRand, message, n);

        // digest = H_msg(R, pk_seed, pk_root, M)
        int mdLen = (p.K * p.A + 7) / 8;  // FORS message length
        int treeBytes = (p.H - p.HPrime + 7) / 8;
        int leafBytes = (p.HPrime + 7) / 8;
        int digestLen = mdLen + treeBytes + leafBytes;
        byte[] digest = hash.Hmsg(R, pkSeed, pkRoot, message, digestLen);

        byte[] md = digest[..mdLen];
        long idxTree = BytesToLong(digest, mdLen, treeBytes) & ((1L << (p.H - p.HPrime)) - 1);
        int idxLeaf = (int)(BytesToLong(digest, mdLen + treeBytes, leafBytes) & ((1L << p.HPrime) - 1));

        // FORS sign
        Address adrs = new();
        adrs.SetLayerAddress(0);
        adrs.SetTreeAddress(idxTree);
        adrs.SetType(Address.ForsTree);
        adrs.SetKeyPairAddress(idxLeaf);

        var (forsSks, forsAuthPaths) = Fors.Sign(hash, pkSeed, skSeed, md, adrs, p);
        byte[] forsPk = Fors.PkFromSig(hash, pkSeed, forsSks, forsAuthPaths, md, adrs, p);

        // Hypertree sign on FORS public key
        byte[] htSig = Hypertree.Sign(hash, pkSeed, skSeed, forsPk, idxTree, idxLeaf, p);

        // Assemble signature: R || FORS sig || HT sig
        using var sigStream = new MemoryStream();
        sigStream.Write(R);
        // FORS signature
        for (int i = 0; i < p.A; i++)
        {
            sigStream.Write(forsSks[i]);
            for (int j = 0; j < p.K; j++)
                sigStream.Write(forsAuthPaths[i][j]);
        }
        sigStream.Write(htSig);

        return sigStream.ToArray();
    }

    /// <summary>SLH-DSA.Verify: returns true if signature is valid.</summary>
    public static bool Verify(SlhParams p, byte[] pk, byte[] message, byte[] sig)
    {
        int n = p.N;
        byte[] pkSeed = pk[..n];
        byte[] pkRoot = pk[n..];

        var hash = GetHashSuite(p);

        int offset = 0;
        byte[] R = sig[offset..(offset + n)];
        offset += n;

        // Recompute digest
        int mdLen = (p.K * p.A + 7) / 8;
        int treeBytes = (p.H - p.HPrime + 7) / 8;
        int leafBytes = (p.HPrime + 7) / 8;
        int digestLen = mdLen + treeBytes + leafBytes;
        byte[] digest = hash.Hmsg(R, pkSeed, pkRoot, message, digestLen);

        byte[] md = digest[..mdLen];
        long idxTree = BytesToLong(digest, mdLen, treeBytes) & ((1L << (p.H - p.HPrime)) - 1);
        int idxLeaf = (int)(BytesToLong(digest, mdLen + treeBytes, leafBytes) & ((1L << p.HPrime) - 1));

        // Parse FORS signature
        byte[][] forsSks = new byte[p.A][];
        byte[][][] forsAuthPaths = new byte[p.A][][];
        for (int i = 0; i < p.A; i++)
        {
            forsSks[i] = sig[offset..(offset + n)];
            offset += n;
            forsAuthPaths[i] = new byte[p.K][];
            for (int j = 0; j < p.K; j++)
            {
                forsAuthPaths[i][j] = sig[offset..(offset + n)];
                offset += n;
            }
        }

        // Recover FORS public key
        Address adrs = new();
        adrs.SetLayerAddress(0);
        adrs.SetTreeAddress(idxTree);
        adrs.SetType(Address.ForsTree);
        adrs.SetKeyPairAddress(idxLeaf);
        byte[] forsPk = Fors.PkFromSig(hash, pkSeed, forsSks, forsAuthPaths, md, adrs, p);

        // Verify hypertree signature
        byte[] htSig = sig[offset..];
        return Hypertree.Verify(hash, pkSeed, forsPk, htSig, idxTree, idxLeaf, pkRoot, p);
    }

    private static long BytesToLong(byte[] buf, int offset, int len)
    {
        long val = 0;
        for (int i = 0; i < len && (offset + i) < buf.Length; i++)
            val = (val << 8) | buf[offset + i];
        return val;
    }
}

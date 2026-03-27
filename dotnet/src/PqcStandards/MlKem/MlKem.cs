using System.Security.Cryptography;

namespace PqcStandards.MlKem;

/// <summary>ML-KEM (FIPS 203) key encapsulation mechanism.</summary>
public static class MlKemAlgorithm
{
    /// <summary>ML-KEM.KeyGen: returns (encapsulation key ek, decapsulation key dk).</summary>
    public static (byte[] ek, byte[] dk) KeyGen(MlKemParams p)
    {
        byte[] d = RandomNumberGenerator.GetBytes(32);
        byte[] z = RandomNumberGenerator.GetBytes(32);
        return KeyGenInternal(p, d, z);
    }

    internal static (byte[] ek, byte[] dk) KeyGenInternal(MlKemParams p, byte[] d, byte[] z)
    {
        var (ekPke, dkPke) = Kpke.KeyGen(p, d);
        byte[] ekHash = HashFuncs.H(ekPke);

        // dk = (dk_pke || ek_pke || H(ek) || z)
        byte[] dk = new byte[dkPke.Length + ekPke.Length + 32 + 32];
        Buffer.BlockCopy(dkPke, 0, dk, 0, dkPke.Length);
        Buffer.BlockCopy(ekPke, 0, dk, dkPke.Length, ekPke.Length);
        Buffer.BlockCopy(ekHash, 0, dk, dkPke.Length + ekPke.Length, 32);
        Buffer.BlockCopy(z, 0, dk, dkPke.Length + ekPke.Length + 32, 32);

        return (ekPke, dk);
    }

    /// <summary>ML-KEM.Encaps: returns (shared secret K, ciphertext ct).</summary>
    public static (byte[] K, byte[] ct) Encaps(MlKemParams p, byte[] ek)
    {
        byte[] m = RandomNumberGenerator.GetBytes(32);
        return EncapsInternal(p, ek, m);
    }

    internal static (byte[] K, byte[] ct) EncapsInternal(MlKemParams p, byte[] ek, byte[] m)
    {
        byte[] ekHash = HashFuncs.H(ek);
        byte[] gInput = new byte[m.Length + ekHash.Length];
        Buffer.BlockCopy(m, 0, gInput, 0, m.Length);
        Buffer.BlockCopy(ekHash, 0, gInput, m.Length, ekHash.Length);
        byte[] g = HashFuncs.G(gInput);
        byte[] K = g[..32];
        byte[] r = g[32..];

        byte[] ct = Kpke.Encrypt(p, ek, m, r);
        return (K, ct);
    }

    /// <summary>ML-KEM.Decaps: returns shared secret K.</summary>
    public static byte[] Decaps(MlKemParams p, byte[] dk, byte[] ct)
    {
        int dkPkeLen = 384 * p.K;
        int ekLen = 384 * p.K + 32;

        byte[] dkPke = dk[..dkPkeLen];
        byte[] ekPke = dk[dkPkeLen..(dkPkeLen + ekLen)];
        byte[] h = dk[(dkPkeLen + ekLen)..(dkPkeLen + ekLen + 32)];
        byte[] z = dk[(dkPkeLen + ekLen + 32)..];

        // Decrypt to get m'
        byte[] mPrime = Kpke.Decrypt(p, dkPke, ct);

        // (K', r') = G(m' || h)
        byte[] gInput = new byte[mPrime.Length + h.Length];
        Buffer.BlockCopy(mPrime, 0, gInput, 0, mPrime.Length);
        Buffer.BlockCopy(h, 0, gInput, mPrime.Length, h.Length);
        byte[] g = HashFuncs.G(gInput);
        byte[] Kprime = g[..32];
        byte[] rPrime = g[32..];

        // Re-encrypt
        byte[] ctPrime = Kpke.Encrypt(p, ekPke, mPrime, rPrime);

        // Constant-time comparison
        bool equal = CryptographicOperations.FixedTimeEquals(ct, ctPrime);

        // Implicit rejection: J(z || ct)
        byte[] jInput = new byte[z.Length + ct.Length];
        Buffer.BlockCopy(z, 0, jInput, 0, z.Length);
        Buffer.BlockCopy(ct, 0, jInput, z.Length, ct.Length);
        byte[] Kbar = HashFuncs.J(jInput);

        // Return K' if ct matches, else Kbar (implicit rejection)
        byte[] result = new byte[32];
        for (int i = 0; i < 32; i++)
            result[i] = equal ? Kprime[i] : Kbar[i];

        return result;
    }
}

using System.Security.Cryptography;

namespace PqcStandards.MlDsa;

/// <summary>Encoding functions for ML-DSA.</summary>
public static class DsaEncode
{
    /// <summary>Bit-pack a polynomial with coefficients in [0, bound).</summary>
    public static byte[] BitPack(int[] poly, int bitLen)
    {
        byte[] buf = new byte[(256 * bitLen + 7) / 8];
        for (int i = 0; i < 256; i++)
        {
            long val = poly[i];
            for (int b = 0; b < bitLen; b++)
            {
                int idx = (i * bitLen + b);
                buf[idx / 8] |= (byte)(((val >> b) & 1) << (idx % 8));
            }
        }
        return buf;
    }

    /// <summary>Bit-unpack a polynomial.</summary>
    public static int[] BitUnpack(byte[] buf, int bitLen)
    {
        int[] poly = new int[256];
        for (int i = 0; i < 256; i++)
        {
            long val = 0;
            for (int b = 0; b < bitLen; b++)
            {
                int idx = i * bitLen + b;
                val |= (long)((buf[idx / 8] >> (idx % 8)) & 1) << b;
            }
            poly[i] = (int)val;
        }
        return poly;
    }

    /// <summary>Encode public key: (rho || t1_encoded).</summary>
    public static byte[] EncodePk(byte[] rho, int[][] t1, int k)
    {
        using var ms = new MemoryStream();
        ms.Write(rho);
        // t1 coefficients need 10 bits each
        for (int i = 0; i < k; i++)
            ms.Write(BitPack(t1[i], 10));
        return ms.ToArray();
    }

    /// <summary>Decode public key.</summary>
    public static (byte[] rho, int[][] t1) DecodePk(byte[] pk, int k)
    {
        byte[] rho = pk[..32];
        int[][] t1 = new int[k][];
        int polyBytes = 320; // 256 * 10 / 8
        for (int i = 0; i < k; i++)
            t1[i] = BitUnpack(pk[(32 + i * polyBytes)..(32 + (i + 1) * polyBytes)], 10);
        return (rho, t1);
    }

    /// <summary>Encode secret key.</summary>
    public static byte[] EncodeSk(byte[] rho, byte[] K, byte[] tr, int[][] s1, int[][] s2, int[][] t0, int k, int l, int eta)
    {
        using var ms = new MemoryStream();
        ms.Write(rho);           // 32 bytes
        ms.Write(K);             // 32 bytes
        ms.Write(tr);            // 64 bytes

        int etaBits = eta == 2 ? 3 : 4;
        for (int i = 0; i < l; i++)
        {
            int[] shifted = new int[256];
            for (int j = 0; j < 256; j++)
                shifted[j] = eta - DsaField.CenterMod(s1[i][j]);
            ms.Write(BitPack(shifted, etaBits));
        }
        for (int i = 0; i < k; i++)
        {
            int[] shifted = new int[256];
            for (int j = 0; j < 256; j++)
                shifted[j] = eta - DsaField.CenterMod(s2[i][j]);
            ms.Write(BitPack(shifted, etaBits));
        }
        // t0: 13 bits, shifted by 2^12
        for (int i = 0; i < k; i++)
        {
            int[] shifted = new int[256];
            for (int j = 0; j < 256; j++)
                shifted[j] = (1 << 12) - DsaField.CenterMod(t0[i][j]);
            ms.Write(BitPack(shifted, 13));
        }
        return ms.ToArray();
    }

    /// <summary>Decode secret key.</summary>
    public static (byte[] rho, byte[] K, byte[] tr, int[][] s1, int[][] s2, int[][] t0) DecodeSk(
        byte[] sk, int k, int l, int eta)
    {
        byte[] rho = sk[..32];
        byte[] K = sk[32..64];
        byte[] tr = sk[64..128];

        int etaBits = eta == 2 ? 3 : 4;
        int polyBytesSe = (256 * etaBits + 7) / 8;
        int offset = 128;

        int[][] s1 = new int[l][];
        for (int i = 0; i < l; i++)
        {
            int[] raw = BitUnpack(sk[offset..(offset + polyBytesSe)], etaBits);
            s1[i] = new int[256];
            for (int j = 0; j < 256; j++)
                s1[i][j] = DsaField.ModQ(eta - raw[j]);
            offset += polyBytesSe;
        }

        int[][] s2 = new int[k][];
        for (int i = 0; i < k; i++)
        {
            int[] raw = BitUnpack(sk[offset..(offset + polyBytesSe)], etaBits);
            s2[i] = new int[256];
            for (int j = 0; j < 256; j++)
                s2[i][j] = DsaField.ModQ(eta - raw[j]);
            offset += polyBytesSe;
        }

        int polyBytesT0 = (256 * 13 + 7) / 8;
        int[][] t0 = new int[k][];
        for (int i = 0; i < k; i++)
        {
            int[] raw = BitUnpack(sk[offset..(offset + polyBytesT0)], 13);
            t0[i] = new int[256];
            for (int j = 0; j < 256; j++)
                t0[i][j] = DsaField.ModQ((1 << 12) - raw[j]);
            offset += polyBytesT0;
        }
        return (rho, K, tr, s1, s2, t0);
    }

    /// <summary>Encode w1 (high bits of w).</summary>
    public static byte[] EncodeW1(int[][] w1, int k, int gamma2)
    {
        int alpha = 2 * gamma2;
        int m = (DsaField.Q - 1) / alpha;
        int bits = BitsNeeded(m - 1);

        using var ms = new MemoryStream();
        for (int i = 0; i < k; i++)
            ms.Write(BitPack(w1[i], bits));
        return ms.ToArray();
    }

    /// <summary>Encode signature.</summary>
    public static byte[] EncodeSig(byte[] cTilde, int[][] z, int[][] h, MlDsaParams p)
    {
        using var ms = new MemoryStream();
        // c_tilde: lambda/4 bytes
        ms.Write(cTilde);

        // z: each coeff in [-(gamma1-1), gamma1], pack as gamma1 - z
        int gamma1Bits = p.Gamma1 == (1 << 17) ? 18 : 20;
        for (int i = 0; i < p.L; i++)
        {
            int[] shifted = new int[256];
            for (int j = 0; j < 256; j++)
                shifted[j] = p.Gamma1 - DsaField.CenterMod(z[i][j]);
            ms.Write(BitPack(shifted, gamma1Bits));
        }

        // Encode hint h
        byte[] hintBytes = new byte[p.Omega + p.K];
        int idx = 0;
        for (int i = 0; i < p.K; i++)
        {
            for (int j = 0; j < 256; j++)
            {
                if (h[i][j] != 0)
                    hintBytes[idx++] = (byte)j;
            }
            hintBytes[p.Omega + i] = (byte)idx;
        }
        ms.Write(hintBytes);

        return ms.ToArray();
    }

    /// <summary>Decode signature.</summary>
    public static (byte[] cTilde, int[][] z, int[][] h)? DecodeSig(byte[] sig, MlDsaParams p)
    {
        int cTildeLen = p.Lambda / 4;
        byte[] cTilde = sig[..cTildeLen];

        int gamma1Bits = p.Gamma1 == (1 << 17) ? 18 : 20;
        int polyBytes = (256 * gamma1Bits + 7) / 8;
        int offset = cTildeLen;

        int[][] z = new int[p.L][];
        for (int i = 0; i < p.L; i++)
        {
            int[] raw = BitUnpack(sig[offset..(offset + polyBytes)], gamma1Bits);
            z[i] = new int[256];
            for (int j = 0; j < 256; j++)
                z[i][j] = DsaField.ModQ(p.Gamma1 - raw[j]);
            offset += polyBytes;
        }

        // Decode hint
        byte[] hintBytes = sig[offset..(offset + p.Omega + p.K)];
        int[][] h = new int[p.K][];
        for (int i = 0; i < p.K; i++)
            h[i] = new int[256];

        int prevIdx = 0;
        for (int i = 0; i < p.K; i++)
        {
            int limit = hintBytes[p.Omega + i];
            for (int j = prevIdx; j < limit; j++)
                h[i][hintBytes[j]] = 1;
            prevIdx = limit;
        }

        return (cTilde, z, h);
    }

    private static int BitsNeeded(int max)
    {
        int bits = 0;
        while ((1 << bits) <= max) bits++;
        return bits;
    }
}

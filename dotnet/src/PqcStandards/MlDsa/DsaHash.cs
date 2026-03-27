using PqcStandards.Common;

namespace PqcStandards.MlDsa;

/// <summary>Hash/sampling functions for ML-DSA (FIPS 204).</summary>
public static class DsaHash
{
    /// <summary>ExpandA: generate k x l matrix of NTT-domain polynomials from rho.</summary>
    public static int[][] ExpandA(byte[] rho, int k, int l)
    {
        int[][] A = new int[k * l][];
        for (int i = 0; i < k; i++)
            for (int j = 0; j < l; j++)
                A[i * l + j] = RejNttPoly(rho, (byte)j, (byte)i);
        return A;
    }

    private static int[] RejNttPoly(byte[] rho, byte j, byte i)
    {
        byte[] input = new byte[rho.Length + 2];
        Buffer.BlockCopy(rho, 0, input, 0, rho.Length);
        input[rho.Length] = j;
        input[rho.Length + 1] = i;

        byte[] buf = Keccak.Shake128(input, 3 * 256 * 2);
        int[] a = new int[256];
        int ctr = 0, pos = 0;
        while (ctr < 256)
        {
            int val = (buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16)) & 0x7FFFFF;
            pos += 3;
            if (val < DsaField.Q)
                a[ctr++] = val;
        }
        return a;
    }

    /// <summary>ExpandS: generate secret vectors s1 (l polys) and s2 (k polys) from rhoPrime.</summary>
    public static (int[][] s1, int[][] s2) ExpandS(byte[] rhoPrime, int k, int l, int eta)
    {
        int[][] s1 = new int[l][];
        int[][] s2 = new int[k][];
        ushort nonce = 0;
        for (int i = 0; i < l; i++)
            s1[i] = RejBoundedPoly(rhoPrime, nonce++, eta);
        for (int i = 0; i < k; i++)
            s2[i] = RejBoundedPoly(rhoPrime, nonce++, eta);
        return (s1, s2);
    }

    private static int[] RejBoundedPoly(byte[] rhoPrime, ushort nonce, int eta)
    {
        byte[] input = new byte[rhoPrime.Length + 2];
        Buffer.BlockCopy(rhoPrime, 0, input, 0, rhoPrime.Length);
        input[rhoPrime.Length] = (byte)(nonce & 0xFF);
        input[rhoPrime.Length + 1] = (byte)(nonce >> 8);

        int outLen = eta <= 2 ? 128 * 3 : 128 * 3;
        byte[] buf = Keccak.Shake256(input, outLen);

        int[] p = new int[256];
        int ctr = 0, pos = 0;
        while (ctr < 256 && pos < buf.Length)
        {
            if (eta == 2)
            {
                int b = buf[pos++];
                int z0 = b & 0x0F;
                int z1 = b >> 4;
                if (z0 < 15) { p[ctr++] = DsaField.ModQ(CoeffFromHalfByte(z0, eta)); }
                if (ctr < 256 && z1 < 15) { p[ctr++] = DsaField.ModQ(CoeffFromHalfByte(z1, eta)); }
            }
            else // eta == 4
            {
                int b = buf[pos++];
                int z0 = b & 0x0F;
                int z1 = b >> 4;
                if (z0 < 9) { p[ctr++] = DsaField.ModQ(4 - z0); }
                if (ctr < 256 && z1 < 9) { p[ctr++] = DsaField.ModQ(4 - z1); }
            }
        }
        return p;
    }

    private static int CoeffFromHalfByte(int z, int eta)
    {
        if (eta == 2)
        {
            int r = z % 5;
            return 2 - r;
        }
        return 4 - z;
    }

    /// <summary>ExpandMask: generate masking vector y from rhoPrime and kappa.</summary>
    public static int[][] ExpandMask(byte[] rhoPrime, int kappa, int l, int gamma1)
    {
        int[][] y = new int[l][];
        int bitLen = gamma1 == (1 << 17) ? 18 : 20;
        int polyBytes = 32 * bitLen;
        for (int i = 0; i < l; i++)
        {
            ushort nonce = (ushort)(kappa + i);
            byte[] input = new byte[rhoPrime.Length + 2];
            Buffer.BlockCopy(rhoPrime, 0, input, 0, rhoPrime.Length);
            input[rhoPrime.Length] = (byte)(nonce & 0xFF);
            input[rhoPrime.Length + 1] = (byte)(nonce >> 8);
            byte[] buf = Keccak.Shake256(input, polyBytes);
            y[i] = BitUnpackGamma(buf, gamma1, bitLen);
        }
        return y;
    }

    private static int[] BitUnpackGamma(byte[] buf, int gamma1, int bitLen)
    {
        int[] poly = new int[256];
        for (int i = 0; i < 256; i++)
        {
            int bitPos = i * bitLen;
            long val = 0;
            for (int b = 0; b < bitLen; b++)
            {
                int idx = (bitPos + b) / 8;
                int bit = (bitPos + b) % 8;
                if (idx < buf.Length)
                    val |= (long)((buf[idx] >> bit) & 1) << b;
            }
            poly[i] = DsaField.ModQ(gamma1 - (int)val);
        }
        return poly;
    }

    /// <summary>SampleInBall: deterministic sampling of challenge polynomial c.</summary>
    public static int[] SampleInBall(byte[] seed, int tau)
    {
        byte[] buf = Keccak.Shake256(seed, 8 + 256);
        int[] c = new int[256];

        // Extract 8 bytes for sign bits
        ulong signs = 0;
        for (int i = 0; i < 8; i++)
            signs |= (ulong)buf[i] << (8 * i);

        int k = 8;
        for (int i = 256 - tau; i < 256; i++)
        {
            int j;
            do
            {
                j = buf[k++];
                if (k >= buf.Length)
                {
                    buf = Keccak.Shake256(buf, 8 + 256);
                    k = 0;
                }
            } while (j > i);

            c[i] = c[j];
            c[j] = ((signs & 1) == 1) ? DsaField.Q - 1 : 1;
            signs >>= 1;
        }
        return c;
    }
}

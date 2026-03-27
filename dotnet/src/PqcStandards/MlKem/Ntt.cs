namespace PqcStandards.MlKem;

/// <summary>Number-Theoretic Transform for ML-KEM (FIPS 203).</summary>
public static class Ntt
{
    // Precomputed zetas: zeta = 17, zetas[i] = 17^(BitRev7(i)) mod Q
    public static readonly int[] Zetas = ComputeZetas();

    private static int[] ComputeZetas()
    {
        int[] z = new int[128];
        for (int i = 0; i < 128; i++)
            z[i] = Field.FieldPow(17, BitRev7(i));
        return z;
    }

    public static int BitRev7(int x)
    {
        int r = 0;
        for (int i = 0; i < 7; i++)
        {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
        return r;
    }

    /// <summary>Forward NTT: in-place, producing NTT domain polynomial.</summary>
    public static int[] NttForward(int[] f)
    {
        int[] fhat = (int[])f.Clone();
        int k = 1;
        for (int len = 128; len >= 2; len >>= 1)
        {
            for (int start = 0; start < 256; start += 2 * len)
            {
                int zeta = Zetas[k++];
                for (int j = start; j < start + len; j++)
                {
                    int t = Field.FieldMul(zeta, fhat[j + len]);
                    fhat[j + len] = Field.FieldSub(fhat[j], t);
                    fhat[j] = Field.FieldAdd(fhat[j], t);
                }
            }
        }
        return fhat;
    }

    /// <summary>Inverse NTT.</summary>
    public static int[] NttInverse(int[] fhat)
    {
        int[] f = (int[])fhat.Clone();
        int k = 127;
        for (int len = 2; len <= 128; len <<= 1)
        {
            for (int start = 0; start < 256; start += 2 * len)
            {
                int zeta = Zetas[k--];
                for (int j = start; j < start + len; j++)
                {
                    int t = f[j];
                    f[j] = Field.FieldAdd(t, f[j + len]);
                    f[j + len] = Field.FieldMul(zeta, Field.FieldSub(f[j + len], t));
                }
            }
        }
        // Multiply by n^{-1} = 3303 mod Q  (256^{-1} mod 3329)
        int nInv = 3303;
        for (int i = 0; i < 256; i++)
            f[i] = Field.FieldMul(f[i], nInv);
        return f;
    }

    /// <summary>Pointwise multiplication of two NTT-domain polynomials.</summary>
    public static int[] MultiplyNtts(int[] a, int[] b)
    {
        int[] c = new int[256];
        for (int i = 0; i < 64; i++)
        {
            int z = Zetas[64 + i];
            (c[4 * i], c[4 * i + 1]) = BaseCaseMultiply(
                a[4 * i], a[4 * i + 1], b[4 * i], b[4 * i + 1], z);
            (c[4 * i + 2], c[4 * i + 3]) = BaseCaseMultiply(
                a[4 * i + 2], a[4 * i + 3], b[4 * i + 2], b[4 * i + 3],
                Field.FieldSub(0, z));
        }
        return c;
    }

    public static (int, int) BaseCaseMultiply(int a0, int a1, int b0, int b1, int gamma)
    {
        int c0 = Field.FieldAdd(Field.FieldMul(a0, b0), Field.FieldMul(Field.FieldMul(a1, b1), gamma));
        int c1 = Field.FieldAdd(Field.FieldMul(a0, b1), Field.FieldMul(a1, b0));
        return (c0, c1);
    }
}

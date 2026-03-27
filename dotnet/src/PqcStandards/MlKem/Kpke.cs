namespace PqcStandards.MlKem;

/// <summary>K-PKE (internal PKE scheme) for ML-KEM per FIPS 203.</summary>
public static class Kpke
{
    /// <summary>K-PKE.KeyGen: returns (encapsulation key ek, decryption key dk).</summary>
    public static (byte[] ek, byte[] dk) KeyGen(MlKemParams p, byte[] d)
    {
        // (rho, sigma) = G(d || k)
        byte[] gInput = new byte[d.Length + 1];
        Buffer.BlockCopy(d, 0, gInput, 0, d.Length);
        gInput[d.Length] = (byte)p.K;
        byte[] g = HashFuncs.G(gInput);
        byte[] rho = g[..32];
        byte[] sigma = g[32..];

        // Generate A hat (in NTT domain)
        int[][] Ahat = new int[p.K * p.K][];
        for (int i = 0; i < p.K; i++)
            for (int j = 0; j < p.K; j++)
                Ahat[i * p.K + j] = Sampling.SampleNtt(rho, (byte)j, (byte)i);

        // Generate s (secret) and e (error)
        int[][] s = new int[p.K][];
        int[][] e = new int[p.K][];
        byte N = 0;
        for (int i = 0; i < p.K; i++)
            s[i] = Sampling.SamplePolyCbd(sigma, N++, p.Eta1);
        for (int i = 0; i < p.K; i++)
            e[i] = Sampling.SamplePolyCbd(sigma, N++, p.Eta1);

        // NTT(s), NTT(e)
        int[][] shat = new int[p.K][];
        int[][] ehat = new int[p.K][];
        for (int i = 0; i < p.K; i++)
        {
            shat[i] = Ntt.NttForward(s[i]);
            ehat[i] = Ntt.NttForward(e[i]);
        }

        // t_hat = A_hat * s_hat + e_hat
        int[][] that = new int[p.K][];
        for (int i = 0; i < p.K; i++)
        {
            that[i] = new int[256];
            for (int j = 0; j < p.K; j++)
            {
                int[] prod = Ntt.MultiplyNtts(Ahat[i * p.K + j], shat[j]);
                for (int c = 0; c < 256; c++)
                    that[i][c] = Field.FieldAdd(that[i][c], prod[c]);
            }
            for (int c = 0; c < 256; c++)
                that[i][c] = Field.FieldAdd(that[i][c], ehat[i][c]);
        }

        // Encode ek = (ByteEncode12(t_hat) || rho)
        using var ekStream = new MemoryStream();
        for (int i = 0; i < p.K; i++)
            ekStream.Write(Encode.ByteEncode(that[i], 12));
        ekStream.Write(rho);
        byte[] ek = ekStream.ToArray();

        // Encode dk = ByteEncode12(s_hat)
        using var dkStream = new MemoryStream();
        for (int i = 0; i < p.K; i++)
            dkStream.Write(Encode.ByteEncode(shat[i], 12));
        byte[] dk = dkStream.ToArray();

        return (ek, dk);
    }

    /// <summary>K-PKE.Encrypt.</summary>
    public static byte[] Encrypt(MlKemParams p, byte[] ek, byte[] m, byte[] r)
    {
        // Parse ek
        int[][] that = new int[p.K][];
        for (int i = 0; i < p.K; i++)
            that[i] = Encode.ByteDecode(ek[(384 * i)..(384 * (i + 1))], 12);
        byte[] rho = ek[(384 * p.K)..];

        // Regenerate A_hat (transposed compared to keygen)
        int[][] Ahat = new int[p.K * p.K][];
        for (int i = 0; i < p.K; i++)
            for (int j = 0; j < p.K; j++)
                Ahat[i * p.K + j] = Sampling.SampleNtt(rho, (byte)i, (byte)j);

        // Sample r_vec, e1, e2
        int[][] rvec = new int[p.K][];
        int[][] e1 = new int[p.K][];
        byte N = 0;
        for (int i = 0; i < p.K; i++)
            rvec[i] = Sampling.SamplePolyCbd(r, N++, p.Eta1);
        for (int i = 0; i < p.K; i++)
            e1[i] = Sampling.SamplePolyCbd(r, N++, p.Eta2);
        int[] e2 = Sampling.SamplePolyCbd(r, N++, p.Eta2);

        // NTT(r_vec)
        int[][] rhat = new int[p.K][];
        for (int i = 0; i < p.K; i++)
            rhat[i] = Ntt.NttForward(rvec[i]);

        // u = NTT^-1(A^T * r_hat) + e1
        int[][] u = new int[p.K][];
        for (int i = 0; i < p.K; i++)
        {
            u[i] = new int[256];
            for (int j = 0; j < p.K; j++)
            {
                int[] prod = Ntt.MultiplyNtts(Ahat[i * p.K + j], rhat[j]);
                for (int c = 0; c < 256; c++)
                    u[i][c] = Field.FieldAdd(u[i][c], prod[c]);
            }
            u[i] = Ntt.NttInverse(u[i]);
            for (int c = 0; c < 256; c++)
                u[i][c] = Field.FieldAdd(u[i][c], e1[i][c]);
        }

        // v = NTT^-1(t_hat . r_hat) + e2 + Decompress(Decode(m, 1), 1)
        int[] v = new int[256];
        for (int j = 0; j < p.K; j++)
        {
            int[] prod = Ntt.MultiplyNtts(that[j], rhat[j]);
            for (int c = 0; c < 256; c++)
                v[c] = Field.FieldAdd(v[c], prod[c]);
        }
        v = Ntt.NttInverse(v);

        int[] mu = Compress.DecompressPoly(Encode.ByteDecode(m, 1), 1);
        for (int c = 0; c < 256; c++)
            v[c] = Field.FieldAdd(Field.FieldAdd(v[c], e2[c]), mu[c]);

        // Encode ciphertext
        using var ctStream = new MemoryStream();
        for (int i = 0; i < p.K; i++)
            ctStream.Write(Encode.ByteEncode(Compress.CompressPoly(u[i], p.Du), p.Du));
        ctStream.Write(Encode.ByteEncode(Compress.CompressPoly(v, p.Dv), p.Dv));
        return ctStream.ToArray();
    }

    /// <summary>K-PKE.Decrypt.</summary>
    public static byte[] Decrypt(MlKemParams p, byte[] dk, byte[] ct)
    {
        // Parse u from ct
        int[][] u = new int[p.K][];
        int uByteLen = 32 * p.Du;
        for (int i = 0; i < p.K; i++)
        {
            int[] compressed = Encode.ByteDecode(ct[(uByteLen * i)..(uByteLen * (i + 1))], p.Du);
            u[i] = Compress.DecompressPoly(compressed, p.Du);
        }

        // Parse v from ct
        int vOffset = uByteLen * p.K;
        int[] vCompressed = Encode.ByteDecode(ct[vOffset..], p.Dv);
        int[] v = Compress.DecompressPoly(vCompressed, p.Dv);

        // Parse s_hat from dk
        int[][] shat = new int[p.K][];
        for (int i = 0; i < p.K; i++)
            shat[i] = Encode.ByteDecode(dk[(384 * i)..(384 * (i + 1))], 12);

        // w = v - NTT^-1(s_hat . NTT(u))
        int[] w = new int[256];
        for (int j = 0; j < p.K; j++)
        {
            int[] uhat = Ntt.NttForward(u[j]);
            int[] prod = Ntt.MultiplyNtts(shat[j], uhat);
            for (int c = 0; c < 256; c++)
                w[c] = Field.FieldAdd(w[c], prod[c]);
        }
        w = Ntt.NttInverse(w);
        for (int c = 0; c < 256; c++)
            w[c] = Field.FieldSub(v[c], w[c]);

        return Encode.ByteEncode(Compress.CompressPoly(w, 1), 1);
    }
}

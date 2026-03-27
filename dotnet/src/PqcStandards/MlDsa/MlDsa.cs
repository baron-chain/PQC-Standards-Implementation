using System.Security.Cryptography;
using PqcStandards.Common;

namespace PqcStandards.MlDsa;

/// <summary>ML-DSA digital signature algorithm (FIPS 204).</summary>
public static class MlDsaAlgorithm
{
    /// <summary>ML-DSA.KeyGen: returns (pk, sk).</summary>
    public static (byte[] pk, byte[] sk) KeyGen(MlDsaParams p)
    {
        byte[] xi = RandomNumberGenerator.GetBytes(32);
        return KeyGenInternal(p, xi);
    }

    internal static (byte[] pk, byte[] sk) KeyGenInternal(MlDsaParams p, byte[] xi)
    {
        // (rho, rhoPrime, K) = H(xi || k || l)
        byte[] input = new byte[xi.Length + 2];
        Buffer.BlockCopy(xi, 0, input, 0, xi.Length);
        input[xi.Length] = (byte)p.K;
        input[xi.Length + 1] = (byte)p.L;
        byte[] h = Keccak.Shake256(input, 128);
        byte[] rho = h[..32];
        byte[] rhoPrime = h[32..96];
        byte[] K = h[96..128];

        // A_hat = ExpandA(rho)
        int[][] Ahat = DsaHash.ExpandA(rho, p.K, p.L);

        // (s1, s2) = ExpandS(rhoPrime)
        var (s1, s2) = DsaHash.ExpandS(rhoPrime, p.K, p.L, p.Eta);

        // s1_hat = NTT(s1)
        int[][] s1hat = new int[p.L][];
        for (int i = 0; i < p.L; i++)
            s1hat[i] = DsaNtt.NttForward(s1[i]);

        // t = NTT^-1(A_hat * s1_hat) + s2
        int[][] t = new int[p.K][];
        for (int i = 0; i < p.K; i++)
        {
            t[i] = new int[256];
            for (int j = 0; j < p.L; j++)
            {
                int[] prod = DsaNtt.PointwiseMul(Ahat[i * p.L + j], s1hat[j]);
                for (int c = 0; c < 256; c++)
                    t[i][c] = DsaField.Add(t[i][c], prod[c]);
            }
            t[i] = DsaNtt.NttInverse(t[i]);
            for (int c = 0; c < 256; c++)
                t[i][c] = DsaField.Add(t[i][c], s2[i][c]);
        }

        // (t1, t0) = Power2Round(t)
        int[][] t1 = new int[p.K][];
        int[][] t0 = new int[p.K][];
        for (int i = 0; i < p.K; i++)
        {
            t1[i] = new int[256];
            t0[i] = new int[256];
            for (int j = 0; j < 256; j++)
            {
                var (hi, lo) = Decompose.Power2Round(t[i][j]);
                t1[i][j] = hi;
                t0[i][j] = DsaField.ModQ(lo);
            }
        }

        byte[] pk = DsaEncode.EncodePk(rho, t1, p.K);
        byte[] tr = Keccak.Shake256(pk, 64);
        byte[] sk = DsaEncode.EncodeSk(rho, K, tr, s1, s2, t0, p.K, p.L, p.Eta);

        return (pk, sk);
    }

    /// <summary>ML-DSA.Sign: returns signature sigma.</summary>
    public static byte[] Sign(MlDsaParams p, byte[] sk, byte[] message)
    {
        var (rho, K, tr, s1, s2, t0) = DsaEncode.DecodeSk(sk, p.K, p.L, p.Eta);

        // mu = H(tr || M)
        byte[] muInput = new byte[tr.Length + message.Length];
        Buffer.BlockCopy(tr, 0, muInput, 0, tr.Length);
        Buffer.BlockCopy(message, 0, muInput, tr.Length, message.Length);
        byte[] mu = Keccak.Shake256(muInput, 64);

        // rho' = H(K || mu)  (deterministic signing)
        byte[] rhoP = new byte[K.Length + mu.Length];
        Buffer.BlockCopy(K, 0, rhoP, 0, K.Length);
        Buffer.BlockCopy(mu, 0, rhoP, K.Length, mu.Length);
        byte[] rhoPrime = Keccak.Shake256(rhoP, 64);

        // A_hat = ExpandA(rho)
        int[][] Ahat = DsaHash.ExpandA(rho, p.K, p.L);

        // NTT of s1, s2, t0
        int[][] s1hat = new int[p.L][];
        int[][] s2hat = new int[p.K][];
        int[][] t0hat = new int[p.K][];
        for (int i = 0; i < p.L; i++)
            s1hat[i] = DsaNtt.NttForward(s1[i]);
        for (int i = 0; i < p.K; i++)
        {
            s2hat[i] = DsaNtt.NttForward(s2[i]);
            t0hat[i] = DsaNtt.NttForward(t0[i]);
        }

        // Rejection sampling loop
        int kappa = 0;
        while (true)
        {
            // y = ExpandMask(rhoPrime, kappa)
            int[][] y = DsaHash.ExpandMask(rhoPrime, kappa, p.L, p.Gamma1);
            kappa += p.L;

            // w = NTT^-1(A_hat * NTT(y))
            int[][] yhat = new int[p.L][];
            for (int i = 0; i < p.L; i++)
                yhat[i] = DsaNtt.NttForward(y[i]);

            int[][] w = new int[p.K][];
            for (int i = 0; i < p.K; i++)
            {
                w[i] = new int[256];
                for (int j = 0; j < p.L; j++)
                {
                    int[] prod = DsaNtt.PointwiseMul(Ahat[i * p.L + j], yhat[j]);
                    for (int ci = 0; ci < 256; ci++)
                        w[i][ci] = DsaField.Add(w[i][ci], prod[ci]);
                }
                w[i] = DsaNtt.NttInverse(w[i]);
            }

            // w1 = HighBits(w)
            int[][] w1 = new int[p.K][];
            for (int i = 0; i < p.K; i++)
            {
                w1[i] = new int[256];
                for (int j = 0; j < 256; j++)
                    w1[i][j] = Decompose.HighBits(w[i][j], p.Gamma2);
            }

            // c_tilde = H(mu || EncodeW1(w1))
            byte[] w1Enc = DsaEncode.EncodeW1(w1, p.K, p.Gamma2);
            byte[] cInput = new byte[mu.Length + w1Enc.Length];
            Buffer.BlockCopy(mu, 0, cInput, 0, mu.Length);
            Buffer.BlockCopy(w1Enc, 0, cInput, mu.Length, w1Enc.Length);
            byte[] cTilde = Keccak.Shake256(cInput, p.Lambda / 4);

            // c = SampleInBall(c_tilde)
            int[] c = DsaHash.SampleInBall(cTilde, p.Tau);
            int[] chat = DsaNtt.NttForward(c);

            // z = y + NTT^-1(c_hat * s1_hat)
            int[][] z = new int[p.L][];
            for (int i = 0; i < p.L; i++)
            {
                int[] cs1 = DsaNtt.NttInverse(DsaNtt.PointwiseMul(chat, s1hat[i]));
                z[i] = new int[256];
                for (int j = 0; j < 256; j++)
                    z[i][j] = DsaField.Add(y[i][j], cs1[j]);
            }

            // Check ||z||_inf < gamma1 - beta
            if (!CheckNormBound(z, p.L, p.Gamma1 - p.Beta))
                continue;

            // r0 = LowBits(w - NTT^-1(c_hat * s2_hat))
            bool reject = false;
            int[][] h = new int[p.K][];
            int hintCount = 0;
            for (int i = 0; i < p.K; i++)
            {
                int[] cs2 = DsaNtt.NttInverse(DsaNtt.PointwiseMul(chat, s2hat[i]));
                int[] r0 = new int[256];
                for (int j = 0; j < 256; j++)
                {
                    int wMinusCss2 = DsaField.Sub(w[i][j], cs2[j]);
                    r0[j] = Decompose.LowBits(wMinusCss2, p.Gamma2);
                }
                // Check ||r0||_inf < gamma2 - beta
                for (int j = 0; j < 256; j++)
                {
                    int centered = DsaField.CenterMod(DsaField.ModQ(r0[j]));
                    if (Math.Abs(centered) >= p.Gamma2 - p.Beta)
                    { reject = true; break; }
                }
                if (reject) break;

                // Compute hint
                int[] ct0 = DsaNtt.NttInverse(DsaNtt.PointwiseMul(chat, t0hat[i]));
                h[i] = new int[256];
                for (int j = 0; j < 256; j++)
                {
                    int wPrime = DsaField.Sub(w[i][j], cs2[j]);
                    h[i][j] = Decompose.MakeHint(DsaField.ModQ(ct0[j]), wPrime, p.Gamma2);
                    hintCount += h[i][j];
                }
            }

            if (reject || hintCount > p.Omega)
                continue;

            // Check ct0 norm
            bool ct0Reject = false;
            for (int i = 0; i < p.K && !ct0Reject; i++)
            {
                int[] ct0 = DsaNtt.NttInverse(DsaNtt.PointwiseMul(chat, t0hat[i]));
                for (int j = 0; j < 256; j++)
                {
                    int centered = DsaField.CenterMod(ct0[j]);
                    if (Math.Abs(centered) >= p.Gamma2)
                    { ct0Reject = true; break; }
                }
            }
            if (ct0Reject) continue;

            return DsaEncode.EncodeSig(cTilde, z, h, p);
        }
    }

    /// <summary>ML-DSA.Verify: returns true if signature is valid.</summary>
    public static bool Verify(MlDsaParams p, byte[] pk, byte[] message, byte[] sig)
    {
        if (sig.Length != p.SigSize) return false;

        var (rho, t1) = DsaEncode.DecodePk(pk, p.K);
        byte[] tr = Keccak.Shake256(pk, 64);

        // mu = H(tr || M)
        byte[] muInput = new byte[tr.Length + message.Length];
        Buffer.BlockCopy(tr, 0, muInput, 0, tr.Length);
        Buffer.BlockCopy(message, 0, muInput, tr.Length, message.Length);
        byte[] mu = Keccak.Shake256(muInput, 64);

        var decoded = DsaEncode.DecodeSig(sig, p);
        if (decoded == null) return false;
        var (cTilde, z, h) = decoded.Value;

        // Check z norm
        if (!CheckNormBound(z, p.L, p.Gamma1 - p.Beta))
            return false;

        // A_hat = ExpandA(rho)
        int[][] Ahat = DsaHash.ExpandA(rho, p.K, p.L);

        // c from c_tilde
        int[] c = DsaHash.SampleInBall(cTilde, p.Tau);
        int[] chat = DsaNtt.NttForward(c);

        // NTT(z)
        int[][] zhat = new int[p.L][];
        for (int i = 0; i < p.L; i++)
            zhat[i] = DsaNtt.NttForward(z[i]);

        // w'_approx = NTT^-1(A_hat * NTT(z) - c_hat * NTT(t1 * 2^d))
        int[][] w1Prime = new int[p.K][];
        for (int i = 0; i < p.K; i++)
        {
            int[] az = new int[256];
            for (int j = 0; j < p.L; j++)
            {
                int[] prod = DsaNtt.PointwiseMul(Ahat[i * p.L + j], zhat[j]);
                for (int c2 = 0; c2 < 256; c2++)
                    az[c2] = DsaField.Add(az[c2], prod[c2]);
            }

            // t1 * 2^13
            int[] t1Shifted = new int[256];
            for (int j = 0; j < 256; j++)
                t1Shifted[j] = DsaField.Mul(t1[i][j], 1 << 13);
            int[] t1hat = DsaNtt.NttForward(t1Shifted);
            int[] ct1 = DsaNtt.PointwiseMul(chat, t1hat);

            int[] wApprox = new int[256];
            for (int j = 0; j < 256; j++)
                wApprox[j] = DsaField.Sub(az[j], ct1[j]);
            wApprox = DsaNtt.NttInverse(wApprox);

            // UseHint to recover w1'
            w1Prime[i] = new int[256];
            for (int j = 0; j < 256; j++)
                w1Prime[i][j] = Decompose.UseHint(h[i][j], wApprox[j], p.Gamma2);
        }

        // c_tilde' = H(mu || EncodeW1(w1'))
        byte[] w1Enc = DsaEncode.EncodeW1(w1Prime, p.K, p.Gamma2);
        byte[] cInput = new byte[mu.Length + w1Enc.Length];
        Buffer.BlockCopy(mu, 0, cInput, 0, mu.Length);
        Buffer.BlockCopy(w1Enc, 0, cInput, mu.Length, w1Enc.Length);
        byte[] cTildePrime = Keccak.Shake256(cInput, p.Lambda / 4);

        return CryptographicOperations.FixedTimeEquals(cTilde, cTildePrime);
    }

    private static bool CheckNormBound(int[][] vecs, int count, int bound)
    {
        for (int i = 0; i < count; i++)
            for (int j = 0; j < 256; j++)
            {
                int centered = DsaField.CenterMod(vecs[i][j]);
                if (Math.Abs(centered) >= bound)
                    return false;
            }
        return true;
    }
}

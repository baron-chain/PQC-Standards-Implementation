namespace PqcStandards.SlhDsa;

/// <summary>WOTS+ one-time signature for SLH-DSA.</summary>
public static class Wots
{
    /// <summary>Iterative hash chain: apply F i times starting from x.</summary>
    public static byte[] Chain(IHashSuite hash, byte[] pkSeed, Address adrs, byte[] x, int i, int steps, int n)
    {
        byte[] tmp = (byte[])x.Clone();
        for (int j = i; j < i + steps; j++)
        {
            adrs.SetHashAddress(j);
            tmp = hash.F(pkSeed, adrs, tmp, n);
        }
        return tmp;
    }

    /// <summary>Generate WOTS+ public key.</summary>
    public static byte[] PkGen(IHashSuite hash, byte[] pkSeed, byte[] skSeed, Address adrs, SlhParams p)
    {
        int w = p.W;
        int len = p.Len;
        int n = p.N;

        byte[][] tmp = new byte[len][];
        for (int i = 0; i < len; i++)
        {
            adrs.SetChainAddress(i);
            byte[] sk = hash.Prf(pkSeed, skSeed, adrs, n);
            tmp[i] = Chain(hash, pkSeed, adrs, sk, 0, w - 1, n);
        }

        // Compress
        adrs.SetType(Address.WotsPk);
        adrs.SetKeyPairAddress(GetKp(adrs));
        byte[] concat = Flatten(tmp, n);
        return hash.Tl(pkSeed, adrs, concat, n);
    }

    /// <summary>WOTS+ Sign a message digest.</summary>
    public static byte[][] Sign(IHashSuite hash, byte[] pkSeed, byte[] skSeed, byte[] msg, Address adrs, SlhParams p)
    {
        int w = p.W;
        int len = p.Len;
        int n = p.N;

        int[] baseW = BaseW(msg, w, len, n);

        byte[][] sig = new byte[len][];
        for (int i = 0; i < len; i++)
        {
            adrs.SetChainAddress(i);
            byte[] sk = hash.Prf(pkSeed, skSeed, adrs, n);
            sig[i] = Chain(hash, pkSeed, adrs, sk, 0, baseW[i], n);
        }
        return sig;
    }

    /// <summary>Compute WOTS+ public key from signature.</summary>
    public static byte[] PkFromSig(IHashSuite hash, byte[] pkSeed, byte[][] sig, byte[] msg, Address adrs, SlhParams p)
    {
        int w = p.W;
        int len = p.Len;
        int n = p.N;

        int[] baseW = BaseW(msg, w, len, n);

        byte[][] tmp = new byte[len][];
        for (int i = 0; i < len; i++)
        {
            adrs.SetChainAddress(i);
            tmp[i] = Chain(hash, pkSeed, adrs, sig[i], baseW[i], w - 1 - baseW[i], n);
        }

        adrs.SetType(Address.WotsPk);
        adrs.SetKeyPairAddress(GetKp(adrs));
        byte[] concat = Flatten(tmp, n);
        return hash.Tl(pkSeed, adrs, concat, n);
    }

    /// <summary>Convert message to base-w representation with checksum.</summary>
    internal static int[] BaseW(byte[] msg, int w, int len, int n)
    {
        int lgW = (int)Math.Log2(w);
        int len1 = (8 * n + lgW - 1) / lgW;
        int len2 = len - len1;

        int[] result = new int[len];

        // Message part
        int bits = 0, total = 0, inIdx = 0;
        for (int i = 0; i < len1; i++)
        {
            while (bits < lgW && inIdx < msg.Length)
            {
                total = (total << 8) | msg[inIdx++];
                bits += 8;
            }
            bits -= lgW;
            result[i] = (total >> bits) & (w - 1);
        }

        // Checksum
        int csum = 0;
        for (int i = 0; i < len1; i++)
            csum += (w - 1) - result[i];

        // Pad checksum to fill len2 base-w digits
        csum <<= (8 - ((len2 * lgW) % 8)) % 8;
        int csumBytes = (len2 * lgW + 7) / 8;
        byte[] csumBuf = new byte[csumBytes];
        for (int i = csumBytes - 1; i >= 0; i--)
        {
            csumBuf[i] = (byte)(csum & 0xFF);
            csum >>= 8;
        }

        bits = 0; total = 0; inIdx = 0;
        for (int i = 0; i < len2; i++)
        {
            while (bits < lgW && inIdx < csumBuf.Length)
            {
                total = (total << 8) | csumBuf[inIdx++];
                bits += 8;
            }
            bits -= lgW;
            result[len1 + i] = (total >> bits) & (w - 1);
        }

        return result;
    }

    private static byte[] Flatten(byte[][] arrays, int n)
    {
        byte[] result = new byte[arrays.Length * n];
        for (int i = 0; i < arrays.Length; i++)
            Buffer.BlockCopy(arrays[i], 0, result, i * n, n);
        return result;
    }

    private static int GetKp(Address adrs)
    {
        // Extract keypair address from bytes 16-19
        return (adrs.Data[16] << 24) | (adrs.Data[17] << 16) | (adrs.Data[18] << 8) | adrs.Data[19];
    }
}

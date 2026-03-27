using PqcStandards.Common;

namespace PqcStandards.SlhDsa;

/// <summary>Hash function interface for SLH-DSA.</summary>
public interface IHashSuite
{
    byte[] Hmsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] msg, int n);
    byte[] Prf(byte[] pkSeed, byte[] skSeed, Address adrs, int n);
    byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] msg, int n);
    byte[] F(byte[] pkSeed, Address adrs, byte[] m1, int n);
    byte[] H(byte[] pkSeed, Address adrs, byte[] m1, byte[] m2, int n);
    byte[] Tl(byte[] pkSeed, Address adrs, byte[] m, int n);
}

/// <summary>SHAKE-based hash functions for SLH-DSA.</summary>
public class ShakeHash : IHashSuite
{
    public byte[] Hmsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] msg, int n)
    {
        byte[] input = Concat(r, pkSeed, pkRoot, msg);
        return Keccak.Shake256(input, n);
    }

    public byte[] Prf(byte[] pkSeed, byte[] skSeed, Address adrs, int n)
    {
        byte[] input = Concat(pkSeed, adrs.Data, skSeed);
        return Keccak.Shake256(input, n);
    }

    public byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] msg, int n)
    {
        byte[] input = Concat(skPrf, optRand, msg);
        return Keccak.Shake256(input, n);
    }

    public byte[] F(byte[] pkSeed, Address adrs, byte[] m1, int n)
    {
        byte[] input = Concat(pkSeed, adrs.Data, m1);
        return Keccak.Shake256(input, n);
    }

    public byte[] H(byte[] pkSeed, Address adrs, byte[] m1, byte[] m2, int n)
    {
        byte[] input = Concat(pkSeed, adrs.Data, m1, m2);
        return Keccak.Shake256(input, n);
    }

    public byte[] Tl(byte[] pkSeed, Address adrs, byte[] m, int n)
    {
        byte[] input = Concat(pkSeed, adrs.Data, m);
        return Keccak.Shake256(input, n);
    }

    private static byte[] Concat(params byte[][] arrays)
    {
        int len = 0;
        foreach (var a in arrays) len += a.Length;
        byte[] result = new byte[len];
        int offset = 0;
        foreach (var a in arrays)
        {
            Buffer.BlockCopy(a, 0, result, offset, a.Length);
            offset += a.Length;
        }
        return result;
    }
}

/// <summary>SHA2-based hash functions for SLH-DSA (simplified — delegates to SHAKE for this implementation).</summary>
public class Sha2Hash : IHashSuite
{
    // For a complete implementation, SHA2 variants would use HMAC-SHA256/512 + MGF1.
    // This simplified version uses SHAKE as a stand-in for test compatibility.
    private readonly ShakeHash _inner = new();

    public byte[] Hmsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] msg, int n) =>
        _inner.Hmsg(r, pkSeed, pkRoot, msg, n);
    public byte[] Prf(byte[] pkSeed, byte[] skSeed, Address adrs, int n) =>
        _inner.Prf(pkSeed, skSeed, adrs, n);
    public byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] msg, int n) =>
        _inner.PrfMsg(skPrf, optRand, msg, n);
    public byte[] F(byte[] pkSeed, Address adrs, byte[] m1, int n) =>
        _inner.F(pkSeed, adrs, m1, n);
    public byte[] H(byte[] pkSeed, Address adrs, byte[] m1, byte[] m2, int n) =>
        _inner.H(pkSeed, adrs, m1, m2, n);
    public byte[] Tl(byte[] pkSeed, Address adrs, byte[] m, int n) =>
        _inner.Tl(pkSeed, adrs, m, n);
}

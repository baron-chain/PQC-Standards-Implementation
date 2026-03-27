using PqcStandards.Common;

namespace PqcStandards.MlKem;

/// <summary>Hash helper functions for ML-KEM using SHA-3 / SHAKE.</summary>
public static class HashFuncs
{
    /// <summary>G: SHA3-512</summary>
    public static byte[] G(byte[] input)
    {
        return Keccak.Sha3_512(input);
    }

    /// <summary>H: SHA3-256</summary>
    public static byte[] H(byte[] input)
    {
        return Keccak.Sha3_256(input);
    }

    /// <summary>J: SHAKE-256 with 32 bytes output</summary>
    public static byte[] J(byte[] input)
    {
        return Keccak.Shake256(input, 32);
    }

    /// <summary>XOF: SHAKE-128 stream</summary>
    public static byte[] Xof(byte[] input, int outputLen)
    {
        return Keccak.Shake128(input, outputLen);
    }

    /// <summary>PRF: SHAKE-256 with configurable output length</summary>
    public static byte[] Prf(byte[] key, byte nonce, int outputLen)
    {
        byte[] input = new byte[key.Length + 1];
        Buffer.BlockCopy(key, 0, input, 0, key.Length);
        input[key.Length] = nonce;
        return Keccak.Shake256(input, outputLen);
    }
}

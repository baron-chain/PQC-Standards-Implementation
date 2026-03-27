namespace PqcStandards.Common;

/// <summary>
/// Pure managed implementation of Keccak-f[1600] permutation and
/// SHA-3 / SHAKE XOF functions.  Replaces System.Security.Cryptography
/// Shake128/Shake256/SHA3_256/SHA3_512 which throw PlatformNotSupportedException
/// on macOS (and older Windows / Linux without OpenSSL 3.x).
/// </summary>
public static class Keccak
{
    // ---------------------------------------------------------------
    //  Public API
    // ---------------------------------------------------------------

    /// <summary>SHAKE-128 extendable output function.</summary>
    public static byte[] Shake128(byte[] input, int outputLength)
        => Sponge(input, outputLength, rate: 168, domainSuffix: 0x1F);

    /// <summary>SHAKE-256 extendable output function.</summary>
    public static byte[] Shake256(byte[] input, int outputLength)
        => Sponge(input, outputLength, rate: 136, domainSuffix: 0x1F);

    /// <summary>SHA3-256 fixed-output hash (32 bytes).</summary>
    public static byte[] Sha3_256(byte[] input)
        => Sponge(input, outputLength: 32, rate: 136, domainSuffix: 0x06);

    /// <summary>SHA3-512 fixed-output hash (64 bytes).</summary>
    public static byte[] Sha3_512(byte[] input)
        => Sponge(input, outputLength: 64, rate: 72, domainSuffix: 0x06);

    // ---------------------------------------------------------------
    //  Sponge construction
    // ---------------------------------------------------------------

    private static byte[] Sponge(byte[] input, int outputLength, int rate, byte domainSuffix)
    {
        // State: 25 x 64-bit words = 200 bytes
        ulong[] state = new ulong[25];

        int blockSize = rate;
        int offset = 0;
        int remaining = input.Length;

        // --- Absorb phase ---
        // Process full blocks
        while (remaining >= blockSize)
        {
            AbsorbBlock(state, input, offset, blockSize);
            KeccakF1600(state);
            offset += blockSize;
            remaining -= blockSize;
        }

        // Pad the final block (pad10*1)
        byte[] lastBlock = new byte[blockSize];
        if (remaining > 0)
            Buffer.BlockCopy(input, offset, lastBlock, 0, remaining);

        lastBlock[remaining] = domainSuffix;
        lastBlock[blockSize - 1] |= 0x80;

        AbsorbBlock(state, lastBlock, 0, blockSize);
        KeccakF1600(state);

        // --- Squeeze phase ---
        byte[] output = new byte[outputLength];
        int squeezed = 0;
        while (squeezed < outputLength)
        {
            int toCopy = Math.Min(blockSize, outputLength - squeezed);
            SqueezeBlock(state, output, squeezed, toCopy);
            squeezed += toCopy;
            if (squeezed < outputLength)
                KeccakF1600(state);
        }

        return output;
    }

    private static void AbsorbBlock(ulong[] state, byte[] data, int offset, int length)
    {
        int laneCount = length / 8;
        for (int i = 0; i < laneCount; i++)
        {
            ulong lane = BitConverter.ToUInt64(data, offset + i * 8);
            state[i] ^= lane;
        }
        // Handle remaining bytes (when length is not a multiple of 8)
        int tail = length % 8;
        if (tail > 0)
        {
            ulong lane = 0;
            int baseOff = offset + laneCount * 8;
            for (int b = 0; b < tail; b++)
                lane |= (ulong)data[baseOff + b] << (8 * b);
            state[laneCount] ^= lane;
        }
    }

    private static void SqueezeBlock(ulong[] state, byte[] output, int offset, int length)
    {
        int laneCount = length / 8;
        for (int i = 0; i < laneCount; i++)
        {
            byte[] bytes = BitConverter.GetBytes(state[i]);
            Buffer.BlockCopy(bytes, 0, output, offset + i * 8, 8);
        }
        int tail = length % 8;
        if (tail > 0)
        {
            byte[] bytes = BitConverter.GetBytes(state[laneCount]);
            Buffer.BlockCopy(bytes, 0, output, offset + laneCount * 8, tail);
        }
    }

    // ---------------------------------------------------------------
    //  Keccak-f[1600] permutation  (24 rounds)
    // ---------------------------------------------------------------

    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001UL, 0x0000000000008082UL,
        0x800000000000808AUL, 0x8000000080008000UL,
        0x000000000000808BUL, 0x0000000080000001UL,
        0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008AUL, 0x0000000000000088UL,
        0x0000000080008009UL, 0x000000008000000AUL,
        0x000000008000808BUL, 0x800000000000008BUL,
        0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL,
        0x000000000000800AUL, 0x800000008000000AUL,
        0x8000000080008081UL, 0x8000000000008080UL,
        0x0000000080000001UL, 0x8000000080008008UL,
    ];

    private static readonly int[] RotationOffsets =
    [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ];

    private static readonly int[] PiLane =
    [
         0, 10,  7, 11, 17,
        18,  3,  5, 16,  8,
        21, 24,  4, 15, 23,
         9, 13, 12, 20, 22,
         1,  6, 19, 14,  2,
    ];

    private static void KeccakF1600(ulong[] state)
    {
        ulong[] C = new ulong[5];
        ulong[] temp = new ulong[25];

        for (int round = 0; round < 24; round++)
        {
            // --- Theta ---
            for (int x = 0; x < 5; x++)
                C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

            for (int x = 0; x < 5; x++)
            {
                ulong d = C[(x + 4) % 5] ^ RotateLeft(C[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5)
                    state[y + x] ^= d;
            }

            // --- Rho + Pi ---
            for (int i = 0; i < 25; i++)
                temp[PiLane[i]] = RotateLeft(state[i], RotationOffsets[i]);

            // --- Chi ---
            for (int y = 0; y < 25; y += 5)
            {
                for (int x = 0; x < 5; x++)
                    state[y + x] = temp[y + x] ^ (~temp[y + (x + 1) % 5] & temp[y + (x + 2) % 5]);
            }

            // --- Iota ---
            state[0] ^= RoundConstants[round];
        }
    }

    private static ulong RotateLeft(ulong value, int offset)
        => (value << offset) | (value >> (64 - offset));
}

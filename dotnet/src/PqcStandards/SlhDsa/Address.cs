namespace PqcStandards.SlhDsa;

/// <summary>ADRS (address) structure for SLH-DSA. 32 bytes, 7 types.</summary>
public class Address
{
    public const int WotsHash = 0;
    public const int WotsPk = 1;
    public const int TreeNode = 2;
    public const int ForsTree = 3;
    public const int ForsPk = 4;
    public const int WotsCompress = 5;
    public const int ForsCompress = 6;

    private readonly byte[] _data = new byte[32];

    public byte[] Data => _data;

    public void SetLayerAddress(int layer)
    {
        _data[0] = (byte)(layer >> 24);
        _data[1] = (byte)(layer >> 16);
        _data[2] = (byte)(layer >> 8);
        _data[3] = (byte)layer;
    }

    public void SetTreeAddress(long tree)
    {
        // Bytes 4-7: zero; bytes 8-15: uint64 big-endian (FIPS 205 Figure 2)
        _data[4] = 0; _data[5] = 0; _data[6] = 0; _data[7] = 0;
        _data[8]  = (byte)(tree >> 56);
        _data[9]  = (byte)(tree >> 48);
        _data[10] = (byte)(tree >> 40);
        _data[11] = (byte)(tree >> 32);
        _data[12] = (byte)(tree >> 24);
        _data[13] = (byte)(tree >> 16);
        _data[14] = (byte)(tree >> 8);
        _data[15] = (byte)tree;
    }

    public void SetType(int type)
    {
        // Bytes 16-19: type; bytes 20-31: zeroed (FIPS 205 Figure 2)
        _data[16] = (byte)(type >> 24);
        _data[17] = (byte)(type >> 16);
        _data[18] = (byte)(type >> 8);
        _data[19] = (byte)type;
        Array.Clear(_data, 20, 12);
    }

    public void SetKeyPairAddress(int kp)
    {
        _data[20] = (byte)(kp >> 24);
        _data[21] = (byte)(kp >> 16);
        _data[22] = (byte)(kp >> 8);
        _data[23] = (byte)kp;
    }

    public int GetKeyPairAddress()
    {
        return (_data[20] << 24) | (_data[21] << 16) | (_data[22] << 8) | _data[23];
    }

    public void SetChainAddress(int chain)
    {
        _data[24] = (byte)(chain >> 24);
        _data[25] = (byte)(chain >> 16);
        _data[26] = (byte)(chain >> 8);
        _data[27] = (byte)chain;
    }

    public void SetHashAddress(int hash)
    {
        _data[28] = (byte)(hash >> 24);
        _data[29] = (byte)(hash >> 16);
        _data[30] = (byte)(hash >> 8);
        _data[31] = (byte)hash;
    }

    public void SetTreeHeight(int height)
    {
        _data[24] = (byte)(height >> 24);
        _data[25] = (byte)(height >> 16);
        _data[26] = (byte)(height >> 8);
        _data[27] = (byte)height;
    }

    public void SetTreeIndex(int index)
    {
        _data[28] = (byte)(index >> 24);
        _data[29] = (byte)(index >> 16);
        _data[30] = (byte)(index >> 8);
        _data[31] = (byte)index;
    }

    public Address Copy()
    {
        var a = new Address();
        Buffer.BlockCopy(_data, 0, a._data, 0, 32);
        return a;
    }
}

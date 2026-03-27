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
        _data[4] = (byte)(tree >> 56);
        _data[5] = (byte)(tree >> 48);
        _data[6] = (byte)(tree >> 40);
        _data[7] = (byte)(tree >> 32);
        _data[8] = (byte)(tree >> 24);
        _data[9] = (byte)(tree >> 16);
        _data[10] = (byte)(tree >> 8);
        _data[11] = (byte)tree;
    }

    public void SetType(int type)
    {
        _data[12] = (byte)(type >> 24);
        _data[13] = (byte)(type >> 16);
        _data[14] = (byte)(type >> 8);
        _data[15] = (byte)type;
        // Clear bytes 16-31 when type changes
        Array.Clear(_data, 16, 16);
    }

    public void SetKeyPairAddress(int kp)
    {
        _data[16] = (byte)(kp >> 24);
        _data[17] = (byte)(kp >> 16);
        _data[18] = (byte)(kp >> 8);
        _data[19] = (byte)kp;
    }

    public void SetChainAddress(int chain)
    {
        _data[20] = (byte)(chain >> 24);
        _data[21] = (byte)(chain >> 16);
        _data[22] = (byte)(chain >> 8);
        _data[23] = (byte)chain;
    }

    public void SetHashAddress(int hash)
    {
        _data[24] = (byte)(hash >> 24);
        _data[25] = (byte)(hash >> 16);
        _data[26] = (byte)(hash >> 8);
        _data[27] = (byte)hash;
    }

    public void SetTreeHeight(int height)
    {
        _data[20] = (byte)(height >> 24);
        _data[21] = (byte)(height >> 16);
        _data[22] = (byte)(height >> 8);
        _data[23] = (byte)height;
    }

    public void SetTreeIndex(int index)
    {
        _data[24] = (byte)(index >> 24);
        _data[25] = (byte)(index >> 16);
        _data[26] = (byte)(index >> 8);
        _data[27] = (byte)index;
    }

    public Address Copy()
    {
        var a = new Address();
        Buffer.BlockCopy(_data, 0, a._data, 0, 32);
        return a;
    }
}

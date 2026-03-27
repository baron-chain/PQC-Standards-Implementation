using PqcStandards.SlhDsa;

namespace PqcStandards.Tests;

public class SlhDsaTests
{
    [Fact]
    public void KeyGen_Sign_Verify_Roundtrip_Shake128f()
    {
        var p = SlhParams.Shake128f;
        var (pk, sk) = SlhDsaAlgorithm.KeyGen(p);

        Assert.Equal(2 * p.N, pk.Length);
        Assert.Equal(4 * p.N, sk.Length);

        byte[] message = "SLH-DSA test message"u8.ToArray();
        byte[] sig = SlhDsaAlgorithm.Sign(p, sk, message);

        bool valid = SlhDsaAlgorithm.Verify(p, pk, message, sig);
        Assert.True(valid);
    }

    [Fact]
    public void Verify_Rejects_Tampered_Message_Shake128f()
    {
        var p = SlhParams.Shake128f;
        var (pk, sk) = SlhDsaAlgorithm.KeyGen(p);
        byte[] message = "Original"u8.ToArray();
        byte[] sig = SlhDsaAlgorithm.Sign(p, sk, message);

        byte[] tampered = "Modified"u8.ToArray();
        bool valid = SlhDsaAlgorithm.Verify(p, pk, tampered, sig);
        Assert.False(valid);
    }

    [Fact]
    public void AllParamSets_HaveCorrectSizes()
    {
        foreach (var p in SlhParams.All)
        {
            Assert.True(p.N > 0, $"{p.Name} N should be positive");
            Assert.True(p.H > 0, $"{p.Name} H should be positive");
            Assert.True(p.D > 0, $"{p.Name} D should be positive");
            Assert.Equal(p.H / p.D, p.HPrime);
            Assert.True(p.SigSize > 0, $"{p.Name} SigSize should be positive");
        }
    }
}

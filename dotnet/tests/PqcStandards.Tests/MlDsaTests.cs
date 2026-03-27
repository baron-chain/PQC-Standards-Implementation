using PqcStandards.MlDsa;

namespace PqcStandards.Tests;

public class MlDsaTests
{
    [Theory]
    [MemberData(nameof(AllParams))]
    public void KeyGen_Sign_Verify_Roundtrip(MlDsaParams p)
    {
        var (pk, sk) = MlDsaAlgorithm.KeyGen(p);
        Assert.Equal(p.PkSize, pk.Length);
        Assert.Equal(p.SkSize, sk.Length);

        byte[] message = "Hello, post-quantum world!"u8.ToArray();
        byte[] sig = MlDsaAlgorithm.Sign(p, sk, message);
        Assert.Equal(p.SigSize, sig.Length);

        bool valid = MlDsaAlgorithm.Verify(p, pk, message, sig);
        Assert.True(valid);
    }

    [Theory]
    [MemberData(nameof(AllParams))]
    public void Verify_Rejects_Tampered_Message(MlDsaParams p)
    {
        var (pk, sk) = MlDsaAlgorithm.KeyGen(p);
        byte[] message = "Original message"u8.ToArray();
        byte[] sig = MlDsaAlgorithm.Sign(p, sk, message);

        byte[] tampered = "Tampered message"u8.ToArray();
        bool valid = MlDsaAlgorithm.Verify(p, pk, tampered, sig);
        Assert.False(valid);
    }

    [Theory]
    [MemberData(nameof(AllParams))]
    public void Verify_Rejects_Tampered_Signature(MlDsaParams p)
    {
        var (pk, sk) = MlDsaAlgorithm.KeyGen(p);
        byte[] message = "Test message"u8.ToArray();
        byte[] sig = MlDsaAlgorithm.Sign(p, sk, message);

        // Tamper signature
        byte[] tampered = (byte[])sig.Clone();
        tampered[sig.Length / 2] ^= 0xFF;

        bool valid = MlDsaAlgorithm.Verify(p, pk, message, tampered);
        Assert.False(valid);
    }

    public static TheoryData<MlDsaParams> AllParams() => new()
    {
        MlDsaParams.MlDsa44,
        MlDsaParams.MlDsa65,
        MlDsaParams.MlDsa87,
    };
}

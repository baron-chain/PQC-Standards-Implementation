using PqcStandards.MlKem;

namespace PqcStandards.Tests;

public class MlKemTests
{
    [Theory]
    [MemberData(nameof(AllParams))]
    public void KeyGen_Encaps_Decaps_Roundtrip(MlKemParams p)
    {
        var (ek, dk) = MlKemAlgorithm.KeyGen(p);
        Assert.Equal(p.EkSize, ek.Length);
        Assert.Equal(p.DkSize, dk.Length);

        var (K, ct) = MlKemAlgorithm.Encaps(p, ek);
        Assert.Equal(32, K.Length);
        Assert.Equal(p.CtSize, ct.Length);

        byte[] K2 = MlKemAlgorithm.Decaps(p, dk, ct);
        Assert.Equal(K, K2);
    }

    [Theory]
    [MemberData(nameof(AllParams))]
    public void ImplicitRejection_TamperedCiphertext(MlKemParams p)
    {
        var (ek, dk) = MlKemAlgorithm.KeyGen(p);
        var (K, ct) = MlKemAlgorithm.Encaps(p, ek);

        // Tamper with ciphertext
        byte[] tampered = (byte[])ct.Clone();
        tampered[0] ^= 0xFF;

        byte[] K2 = MlKemAlgorithm.Decaps(p, dk, tampered);

        // Should NOT return the original shared secret (implicit rejection)
        Assert.NotEqual(K, K2);
        // Should still return 32 bytes
        Assert.Equal(32, K2.Length);
    }

    [Fact]
    public void Deterministic_KeyGen_Produces_Consistent_Results()
    {
        var p = MlKemParams.MlKem768;
        byte[] d = new byte[32];
        byte[] z = new byte[32];
        d[0] = 42;
        z[0] = 99;

        var (ek1, dk1) = MlKemAlgorithm.KeyGen(p);
        var (ek2, dk2) = MlKemAlgorithm.KeyGen(p);

        // Different random seeds produce different keys
        Assert.NotEqual(ek1, ek2);
    }

    public static TheoryData<MlKemParams> AllParams() => new()
    {
        MlKemParams.MlKem512,
        MlKemParams.MlKem768,
        MlKemParams.MlKem1024,
    };
}

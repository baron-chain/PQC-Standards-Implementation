using PqcStandards.Hybrid;

namespace PqcStandards.Tests;

public class HybridTests
{
    [Fact]
    public void X25519MlKem768_Roundtrip()
    {
        var (pk, sk) = HybridKem.X25519MlKem768.KeyGen();
        Assert.NotNull(pk);
        Assert.NotNull(sk);
        Assert.True(pk.Length > 0);
        Assert.True(sk.Length > 0);

        var (sharedSecret, ct) = HybridKem.X25519MlKem768.Encaps(pk);
        Assert.Equal(32, sharedSecret.Length);
        Assert.True(ct.Length > 0);

        byte[] decapsulated = HybridKem.X25519MlKem768.Decaps(sk, ct);
        Assert.Equal(32, decapsulated.Length);
        Assert.Equal(sharedSecret, decapsulated);
    }
}

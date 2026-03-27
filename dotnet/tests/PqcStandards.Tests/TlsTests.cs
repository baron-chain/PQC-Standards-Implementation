using PqcStandards.Tls;

namespace PqcStandards.Tests;

public class TlsTests
{
    [Fact]
    public void NamedGroups_HaveCorrectNames()
    {
        Assert.Equal("ML-KEM-768", NamedGroups.GetName(NamedGroups.MlKem768));
        Assert.Equal("X25519MLKEM768", NamedGroups.GetName(NamedGroups.X25519MlKem768));
        Assert.Equal("x25519", NamedGroups.GetName(NamedGroups.X25519));
    }

    [Fact]
    public void NamedGroups_PqcDetection()
    {
        Assert.True(NamedGroups.IsPqc(NamedGroups.MlKem768));
        Assert.False(NamedGroups.IsPqc(NamedGroups.X25519));
        Assert.True(NamedGroups.IsHybrid(NamedGroups.X25519MlKem768));
        Assert.False(NamedGroups.IsHybrid(NamedGroups.MlKem768));
    }

    [Fact]
    public void SigAlgorithms_HaveCorrectNames()
    {
        Assert.Equal("ML-DSA-65", SigAlgorithms.GetName(SigAlgorithms.MlDsa65));
        Assert.Equal("SLH-DSA-SHAKE-128f", SigAlgorithms.GetName(SigAlgorithms.SlhDsaShake128f));
        Assert.True(SigAlgorithms.IsPqc(SigAlgorithms.MlDsa44));
        Assert.False(SigAlgorithms.IsPqc(SigAlgorithms.Ed25519));
    }

    [Fact]
    public void CipherSuites_Naming()
    {
        Assert.Equal("TLS_AES_256_GCM_SHA384", CipherSuites.GetName(CipherSuites.TLS_AES_256_GCM_SHA384));
        Assert.Equal(3, CipherSuites.Recommended.Length);
    }

    [Fact]
    public void SimulatedKeyExchange_MlKem768_Roundtrip()
    {
        var (clientK, serverK) = CipherSuites.SimulateKeyExchange(NamedGroups.MlKem768);
        Assert.Equal(32, clientK.Length);
        Assert.Equal(32, serverK.Length);
        Assert.Equal(clientK, serverK);
    }
}

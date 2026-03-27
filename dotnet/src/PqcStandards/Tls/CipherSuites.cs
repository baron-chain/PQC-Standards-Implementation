namespace PqcStandards.Tls;

/// <summary>TLS 1.3 cipher suites compatible with PQC.</summary>
public static class CipherSuites
{
    public const ushort TLS_AES_128_GCM_SHA256 = 0x1301;
    public const ushort TLS_AES_256_GCM_SHA384 = 0x1302;
    public const ushort TLS_CHACHA20_POLY1305_SHA256 = 0x1303;

    /// <summary>Get human-readable name.</summary>
    public static string GetName(ushort suite) => suite switch
    {
        TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => $"Unknown(0x{suite:X4})"
    };

    /// <summary>Recommended cipher suites for use with PQC key exchange.</summary>
    public static readonly ushort[] Recommended = [TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256];

    /// <summary>Simulated TLS key exchange using ML-KEM.</summary>
    public static (byte[] clientShared, byte[] serverShared) SimulateKeyExchange(ushort namedGroup)
    {
        if (namedGroup == NamedGroups.MlKem768)
        {
            var p = MlKem.MlKemParams.MlKem768;
            var (ek, dk) = MlKem.MlKemAlgorithm.KeyGen(p);
            var (K, ct) = MlKem.MlKemAlgorithm.Encaps(p, ek);
            byte[] K2 = MlKem.MlKemAlgorithm.Decaps(p, dk, ct);
            return (K, K2);
        }
        throw new NotSupportedException($"Named group 0x{namedGroup:X4} not supported for simulation.");
    }
}

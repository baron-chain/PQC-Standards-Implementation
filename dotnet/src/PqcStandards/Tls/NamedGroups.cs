namespace PqcStandards.Tls;

/// <summary>TLS 1.3 named groups for PQC key exchange (RFC 9180 / draft-ietf-tls-hybrid-design).</summary>
public static class NamedGroups
{
    // Traditional
    public const ushort X25519 = 0x001D;
    public const ushort Secp256r1 = 0x0017;
    public const ushort Secp384r1 = 0x0018;
    public const ushort Secp521r1 = 0x0019;

    // PQC standalone
    public const ushort MlKem512 = 0x0200;
    public const ushort MlKem768 = 0x0201;
    public const ushort MlKem1024 = 0x0202;

    // Hybrid groups
    public const ushort X25519MlKem768 = 0x6399;
    public const ushort Secp256r1MlKem768 = 0x639A;
    public const ushort Secp384r1MlKem1024 = 0x639B;

    /// <summary>Get the human-readable name for a named group.</summary>
    public static string GetName(ushort group) => group switch
    {
        X25519 => "x25519",
        Secp256r1 => "secp256r1",
        Secp384r1 => "secp384r1",
        Secp521r1 => "secp521r1",
        MlKem512 => "ML-KEM-512",
        MlKem768 => "ML-KEM-768",
        MlKem1024 => "ML-KEM-1024",
        X25519MlKem768 => "X25519MLKEM768",
        Secp256r1MlKem768 => "SecP256r1MLKEM768",
        Secp384r1MlKem1024 => "SecP384r1MLKEM1024",
        _ => $"Unknown(0x{group:X4})"
    };

    /// <summary>Check if a group is PQC or hybrid.</summary>
    public static bool IsPqc(ushort group) => group >= 0x0200;

    /// <summary>Check if a group is a hybrid group.</summary>
    public static bool IsHybrid(ushort group) => group >= 0x6399 && group <= 0x639B;

    /// <summary>All supported PQC and hybrid groups.</summary>
    public static readonly ushort[] AllPqcGroups = [MlKem512, MlKem768, MlKem1024, X25519MlKem768, Secp256r1MlKem768, Secp384r1MlKem1024];
}

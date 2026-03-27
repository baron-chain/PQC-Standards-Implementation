namespace PqcStandards.Tls;

/// <summary>TLS 1.3 signature algorithms for PQC.</summary>
public static class SigAlgorithms
{
    // Traditional
    public const ushort EcdsaSecp256r1Sha256 = 0x0403;
    public const ushort EcdsaSecp384r1Sha384 = 0x0503;
    public const ushort Ed25519 = 0x0807;

    // PQC standalone
    public const ushort MlDsa44 = 0x0900;
    public const ushort MlDsa65 = 0x0901;
    public const ushort MlDsa87 = 0x0902;

    // SLH-DSA
    public const ushort SlhDsaShake128f = 0x0904;
    public const ushort SlhDsaShake128s = 0x0905;
    public const ushort SlhDsaShake256f = 0x0906;

    // Composite
    public const ushort MlDsa65EcdsaP256 = 0x0910;
    public const ushort MlDsa87EcdsaP384 = 0x0911;
    public const ushort MlDsa65Ed25519 = 0x0912;

    /// <summary>Get the human-readable name for a signature algorithm.</summary>
    public static string GetName(ushort alg) => alg switch
    {
        EcdsaSecp256r1Sha256 => "ecdsa_secp256r1_sha256",
        EcdsaSecp384r1Sha384 => "ecdsa_secp384r1_sha384",
        Ed25519 => "ed25519",
        MlDsa44 => "ML-DSA-44",
        MlDsa65 => "ML-DSA-65",
        MlDsa87 => "ML-DSA-87",
        SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
        SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
        SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        MlDsa65EcdsaP256 => "ML-DSA-65+ECDSA-P256",
        MlDsa87EcdsaP384 => "ML-DSA-87+ECDSA-P384",
        MlDsa65Ed25519 => "ML-DSA-65+Ed25519",
        _ => $"Unknown(0x{alg:X4})"
    };

    /// <summary>Check if algorithm is PQC.</summary>
    public static bool IsPqc(ushort alg) => alg >= 0x0900;

    /// <summary>All PQC signature algorithms.</summary>
    public static readonly ushort[] AllPqcAlgorithms = [MlDsa44, MlDsa65, MlDsa87, SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake256f, MlDsa65EcdsaP256, MlDsa87EcdsaP384, MlDsa65Ed25519];
}

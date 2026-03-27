namespace PqcStandards.MlDsa;

/// <summary>ML-DSA parameter sets per FIPS 204.</summary>
public sealed record MlDsaParams(
    string Name,
    int Lambda,
    int K,
    int L,
    int Eta,
    int Tau,
    int Beta,
    int Gamma1,
    int Gamma2,
    int Omega,
    int PkSize,
    int SkSize,
    int SigSize)
{
    public static readonly MlDsaParams MlDsa44 = new(
        "ML-DSA-44", 128, 4, 4, 2, 39, 78,
        1 << 17, (DsaField.Q - 1) / 88, 80,
        1312, 2560, 2420);

    public static readonly MlDsaParams MlDsa65 = new(
        "ML-DSA-65", 192, 6, 5, 4, 49, 196,
        1 << 19, (DsaField.Q - 1) / 32, 55,
        1952, 4032, 3309);

    public static readonly MlDsaParams MlDsa87 = new(
        "ML-DSA-87", 256, 8, 7, 2, 60, 120,
        1 << 19, (DsaField.Q - 1) / 32, 75,
        2592, 4896, 4627);
}

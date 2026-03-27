namespace PqcStandards.MlKem;

/// <summary>ML-KEM parameter sets per FIPS 203.</summary>
public sealed record MlKemParams(
    string Name,
    int K,
    int Eta1,
    int Eta2,
    int Du,
    int Dv)
{
    public int EkSize => 384 * K + 32;          // Encapsulation key
    public int DkSize => 768 * K + 96;          // Decapsulation key
    public int CtSize => 32 * (Du * K + Dv);    // Ciphertext

    public static readonly MlKemParams MlKem512 = new("ML-KEM-512", 2, 3, 2, 10, 4);
    public static readonly MlKemParams MlKem768 = new("ML-KEM-768", 3, 2, 2, 10, 4);
    public static readonly MlKemParams MlKem1024 = new("ML-KEM-1024", 4, 2, 2, 11, 5);
}

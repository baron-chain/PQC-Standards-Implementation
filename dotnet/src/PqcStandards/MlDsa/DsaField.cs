namespace PqcStandards.MlDsa;

/// <summary>Field arithmetic modulo Q = 8380417 for ML-DSA.</summary>
public static class DsaField
{
    public const int Q = 8380417;

    public static int ModQ(long a)
    {
        int r = (int)(a % Q);
        return r < 0 ? r + Q : r;
    }

    public static int Add(int a, int b) => ModQ((long)a + b);
    public static int Sub(int a, int b) => ModQ((long)a - b);
    public static int Mul(int a, int b) => ModQ((long)a * b);

    /// <summary>Modular exponentiation.</summary>
    public static int Pow(int a, int exp)
    {
        long result = 1;
        long bas = ModQ(a);
        if (exp < 0) exp += Q - 1;
        while (exp > 0)
        {
            if ((exp & 1) == 1) result = (result * bas) % Q;
            bas = (bas * bas) % Q;
            exp >>= 1;
        }
        return (int)result;
    }

    /// <summary>Centered representative in [-(Q-1)/2, (Q-1)/2].</summary>
    public static int CenterMod(int a)
    {
        int r = a % Q;
        if (r < 0) r += Q;
        return r > Q / 2 ? r - Q : r;
    }
}

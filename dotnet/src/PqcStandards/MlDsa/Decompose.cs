namespace PqcStandards.MlDsa;

/// <summary>Decompose, rounding, and hint functions for ML-DSA.</summary>
public static class Decompose
{
    /// <summary>Power2Round: split r into (r1, r0) where r = r1 * 2^d + r0.</summary>
    public static (int r1, int r0) Power2Round(int r)
    {
        int rPlus = r % DsaField.Q;
        if (rPlus < 0) rPlus += DsaField.Q;
        int r0 = CenterMod(rPlus, 1 << 13);
        return ((rPlus - r0) >> 13, r0);
    }

    /// <summary>Decompose r into (r1, r0) such that r = r1 * alpha + r0, with |r0| &lt;= alpha/2.</summary>
    public static (int r1, int r0) DecomposeValue(int r, int gamma2)
    {
        int rPlus = r % DsaField.Q;
        if (rPlus < 0) rPlus += DsaField.Q;

        int alpha = 2 * gamma2;
        int r0 = CenterMod(rPlus, alpha);
        int r1;

        if (rPlus - r0 == DsaField.Q - 1)
        {
            r1 = 0;
            r0 = -1;
        }
        else
        {
            r1 = (rPlus - r0) / alpha;
        }
        return (r1, r0);
    }

    public static int HighBits(int r, int gamma2) => DecomposeValue(r, gamma2).r1;
    public static int LowBits(int r, int gamma2) => DecomposeValue(r, gamma2).r0;

    /// <summary>MakeHint: returns 1 if UseHint would change the high bits.</summary>
    public static int MakeHint(int z, int r, int gamma2)
    {
        int r1 = HighBits(r, gamma2);
        int v1 = HighBits(DsaField.Add(r, z), gamma2);
        return r1 != v1 ? 1 : 0;
    }

    /// <summary>UseHint: adjust high bits using hint.</summary>
    public static int UseHint(int h, int r, int gamma2)
    {
        var (r1, r0) = DecomposeValue(r, gamma2);
        if (h == 0) return r1;

        int alpha = 2 * gamma2;
        int m = (DsaField.Q - 1) / alpha;

        if (r0 > 0) return (r1 + 1) % m;
        return (r1 - 1 + m) % m;
    }

    private static int CenterMod(int r, int alpha)
    {
        int r0 = r % alpha;
        if (r0 > alpha / 2) r0 -= alpha;
        return r0;
    }
}

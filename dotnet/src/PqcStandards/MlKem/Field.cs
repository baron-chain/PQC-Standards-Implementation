namespace PqcStandards.MlKem;

/// <summary>Field arithmetic modulo Q = 3329 for ML-KEM.</summary>
public static class Field
{
    public const int Q = 3329;

    public static int ModQ(int a)
    {
        int r = a % Q;
        return r < 0 ? r + Q : r;
    }

    public static int FieldAdd(int a, int b) => ModQ(a + b);
    public static int FieldSub(int a, int b) => ModQ(a - b);
    public static int FieldMul(int a, int b) => ModQ(a * b);

    public static int FieldPow(int a, int exp)
    {
        int result = 1;
        a = ModQ(a);
        exp %= (Q - 1);
        if (exp < 0) exp += Q - 1;
        while (exp > 0)
        {
            if ((exp & 1) == 1) result = FieldMul(result, a);
            a = FieldMul(a, a);
            exp >>= 1;
        }
        return result;
    }
}

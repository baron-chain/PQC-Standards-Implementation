using System.Security.Cryptography;
using PqcStandards.MlDsa;

namespace PqcStandards.Composite;

/// <summary>Composite signature scheme: ML-DSA + ECDSA.</summary>
public static class CompositeSig
{
    /// <summary>ML-DSA-65 + ECDSA P-256 composite signature.</summary>
    public static class MlDsa65EcdsaP256
    {
        private static readonly MlDsaParams Params = MlDsaParams.MlDsa65;
        private const int CoordLen = 32;
        // ECDSA sk = D(32) || X(32) || Y(32) = 96 bytes
        private const int EcdsaSkLen = 96;
        private const int EcdsaPubLen = 65; // 0x04 || X || Y

        /// <summary>Generate composite keypair.</summary>
        public static (byte[] pk, byte[] sk) KeyGen()
        {
            var (mldsaPk, mldsaSk) = MlDsaAlgorithm.KeyGen(Params);

            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var ecParams = ecdsa.ExportParameters(true);
            byte[] ecdsaPub = SerializePub(ecParams);
            byte[] ecdsaSk = SerializeSk(ecParams);

            byte[] pk = PackTwo(mldsaPk, ecdsaPub);
            byte[] sk = PackTwo(mldsaSk, ecdsaSk);

            return (pk, sk);
        }

        /// <summary>Sign a message with composite scheme.</summary>
        public static byte[] Sign(byte[] sk, byte[] message)
        {
            var (mldsaSk, ecdsaSkBytes) = UnpackTwo(sk);

            byte[] mldsaSig = MlDsaAlgorithm.Sign(Params, mldsaSk, message);

            using var ecdsa = DeserializeSk(ecdsaSkBytes);
            byte[] ecdsaSig = ecdsa.SignData(message, HashAlgorithmName.SHA256);

            return PackTwo(mldsaSig, ecdsaSig);
        }

        /// <summary>Verify a composite signature.</summary>
        public static bool Verify(byte[] pk, byte[] message, byte[] sig)
        {
            var (mldsaPk, ecdsaPub) = UnpackTwo(pk);
            var (mldsaSig, ecdsaSig) = UnpackTwo(sig);

            bool mldsaValid = MlDsaAlgorithm.Verify(Params, mldsaPk, message, mldsaSig);

            using var ecdsa = DeserializePub(ecdsaPub);
            bool ecdsaValid = ecdsa.VerifyData(message, ecdsaSig, HashAlgorithmName.SHA256);

            return mldsaValid && ecdsaValid;
        }

        private static byte[] SerializePub(ECParameters p)
        {
            byte[] pub = new byte[EcdsaPubLen];
            pub[0] = 0x04;
            Buffer.BlockCopy(p.Q.X!, 0, pub, 1, CoordLen);
            Buffer.BlockCopy(p.Q.Y!, 0, pub, 1 + CoordLen, CoordLen);
            return pub;
        }

        private static byte[] SerializeSk(ECParameters p)
        {
            byte[] sk = new byte[EcdsaSkLen];
            Buffer.BlockCopy(p.D!, 0, sk, 0, CoordLen);
            Buffer.BlockCopy(p.Q.X!, 0, sk, CoordLen, CoordLen);
            Buffer.BlockCopy(p.Q.Y!, 0, sk, 2 * CoordLen, CoordLen);
            return sk;
        }

        private static ECDsa DeserializeSk(byte[] data)
        {
            byte[] d = data[..CoordLen];
            byte[] x = data[CoordLen..(2 * CoordLen)];
            byte[] y = data[(2 * CoordLen)..EcdsaSkLen];
            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = d,
                Q = new ECPoint { X = x, Y = y }
            });
        }

        private static ECDsa DeserializePub(byte[] pub)
        {
            byte[] x = pub[1..(1 + CoordLen)];
            byte[] y = pub[(1 + CoordLen)..];
            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            });
        }

        private static byte[] PackTwo(byte[] a, byte[] b)
        {
            byte[] result = new byte[4 + a.Length + b.Length];
            BitConverter.TryWriteBytes(result.AsSpan(0, 4), a.Length);
            Buffer.BlockCopy(a, 0, result, 4, a.Length);
            Buffer.BlockCopy(b, 0, result, 4 + a.Length, b.Length);
            return result;
        }

        private static (byte[] a, byte[] b) UnpackTwo(byte[] packed)
        {
            int aLen = BitConverter.ToInt32(packed.AsSpan(0, 4));
            byte[] a = packed[4..(4 + aLen)];
            byte[] b = packed[(4 + aLen)..];
            return (a, b);
        }
    }
}

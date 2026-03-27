using System.Security.Cryptography;
using PqcStandards.Common;
using PqcStandards.MlKem;

namespace PqcStandards.Hybrid;

/// <summary>Hybrid KEM combining ECDH (P-256) with ML-KEM.</summary>
public static class HybridKem
{
    /// <summary>ECDH-P256 + ML-KEM-768 hybrid key encapsulation.</summary>
    public static class X25519MlKem768
    {
        private static readonly MlKemParams Params = MlKemParams.MlKem768;
        private const int CoordLen = 32; // P-256 coordinate length
        private const int PubLen = 65;   // 0x04 || X(32) || Y(32)
        // sk stores: D(32) || X(32) || Y(32) = 96 bytes for ECDH part
        private const int EcdhSkLen = CoordLen * 3;

        /// <summary>Generate hybrid keypair.</summary>
        public static (byte[] pk, byte[] sk) KeyGen()
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var ecParams = ecdh.ExportParameters(true);
            byte[] ecdhPub = SerializePub(ecParams);
            byte[] ecdhSk = SerializeSk(ecParams);

            var (mlkemEk, mlkemDk) = MlKemAlgorithm.KeyGen(Params);

            byte[] pk = Concat(ecdhPub, mlkemEk);
            byte[] sk = Concat(ecdhSk, mlkemDk);

            return (pk, sk);
        }

        /// <summary>Encapsulate: returns (sharedSecret, ct).</summary>
        public static (byte[] sharedSecret, byte[] ct) Encaps(byte[] pk)
        {
            byte[] ecdhPeerPub = pk[..PubLen];
            byte[] mlkemEk = pk[PubLen..];

            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            byte[] ecdhEphPub = SerializePub(ecdh.ExportParameters(false));
            byte[] ecdhSs = DeriveSharedSecret(ecdh, ecdhPeerPub);

            var (mlkemSs, mlkemCt) = MlKemAlgorithm.Encaps(Params, mlkemEk);

            byte[] combined = Concat(ecdhSs, mlkemSs);
            byte[] sharedSecret = Keccak.Sha3_256(combined);

            byte[] ct = Concat(ecdhEphPub, mlkemCt);
            return (sharedSecret, ct);
        }

        /// <summary>Decapsulate: returns sharedSecret.</summary>
        public static byte[] Decaps(byte[] sk, byte[] ct)
        {
            byte[] ecdhSkBytes = sk[..EcdhSkLen];
            byte[] mlkemDk = sk[EcdhSkLen..];

            byte[] ecdhEphPub = ct[..PubLen];
            byte[] mlkemCt = ct[PubLen..];

            using var ecdh = DeserializeSk(ecdhSkBytes);
            byte[] ecdhSs = DeriveSharedSecret(ecdh, ecdhEphPub);

            byte[] mlkemSs = MlKemAlgorithm.Decaps(Params, mlkemDk, mlkemCt);

            byte[] combined = Concat(ecdhSs, mlkemSs);
            return Keccak.Sha3_256(combined);
        }

        private static byte[] SerializePub(ECParameters p)
        {
            byte[] pub = new byte[PubLen];
            pub[0] = 0x04;
            Buffer.BlockCopy(p.Q.X!, 0, pub, 1, CoordLen);
            Buffer.BlockCopy(p.Q.Y!, 0, pub, 1 + CoordLen, CoordLen);
            return pub;
        }

        private static byte[] SerializeSk(ECParameters p)
        {
            byte[] sk = new byte[EcdhSkLen];
            Buffer.BlockCopy(p.D!, 0, sk, 0, CoordLen);
            Buffer.BlockCopy(p.Q.X!, 0, sk, CoordLen, CoordLen);
            Buffer.BlockCopy(p.Q.Y!, 0, sk, 2 * CoordLen, CoordLen);
            return sk;
        }

        private static ECDiffieHellman DeserializeSk(byte[] data)
        {
            byte[] d = data[..CoordLen];
            byte[] x = data[CoordLen..(2 * CoordLen)];
            byte[] y = data[(2 * CoordLen)..EcdhSkLen];
            return ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = d,
                Q = new ECPoint { X = x, Y = y }
            });
        }

        private static byte[] DeriveSharedSecret(ECDiffieHellman myKey, byte[] peerPub)
        {
            byte[] x = peerPub[1..(1 + CoordLen)];
            byte[] y = peerPub[(1 + CoordLen)..];
            using var peerKey = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            });
            return myKey.DeriveRawSecretAgreement(peerKey.PublicKey);
        }
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }
}

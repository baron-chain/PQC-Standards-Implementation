package com.pqc.slhdsa;

import com.pqc.common.Keccak;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hash function suites for SLH-DSA per FIPS 205 Sections 11.1 and 11.2.
 */
public interface SlhHash {

    /** PRF(pk.seed, sk.seed, adrs) -> n bytes. */
    byte[] prf(byte[] pkSeed, byte[] skSeed, Address adrs, int n);

    /** PRF_msg(sk.prf, opt_rand, msg) -> n bytes. */
    byte[] prfMsg(byte[] skPrf, byte[] optRand, byte[] msg, int n);

    /** H_msg(r, pk.seed, pk.root, msg) -> m-byte digest. */
    byte[] hMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] msg, int m);

    /** F(pk.seed, adrs, m1) -> n bytes. (Tweakable hash, single block) */
    byte[] f(byte[] pkSeed, Address adrs, byte[] m1, int n);

    /** H(pk.seed, adrs, m1 || m2) -> n bytes. (Tweakable hash, two blocks) */
    byte[] h(byte[] pkSeed, Address adrs, byte[] m1m2, int n);

    /** T_l(pk.seed, adrs, m) -> n bytes. (Tweakable hash, variable length) */
    byte[] tl(byte[] pkSeed, Address adrs, byte[] m, int n);

    /**
     * Create the appropriate hash suite for the given parameters.
     */
    static SlhHash create(SlhParams params) {
        if (params.hashFamily == SlhParams.HashFamily.SHAKE) {
            return new ShakeHash();
        } else {
            return new Sha2Hash(params);
        }
    }

    // ========================================================================
    // SHAKE-based hash suite (FIPS 205, Section 11.1)
    // ========================================================================
    class ShakeHash implements SlhHash {

        @Override
        public byte[] prf(byte[] pkSeed, byte[] skSeed, Address adrs, int n) {
            byte[] input = SlhUtils.concat(pkSeed, adrs.getData(), skSeed);
            return Keccak.shake256(input, n);
        }

        @Override
        public byte[] prfMsg(byte[] skPrf, byte[] optRand, byte[] msg, int n) {
            byte[] input = SlhUtils.concat(skPrf, optRand, msg);
            return Keccak.shake256(input, n);
        }

        @Override
        public byte[] hMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] msg, int m) {
            byte[] input = SlhUtils.concat(r, pkSeed, pkRoot, msg);
            return Keccak.shake256(input, m);
        }

        @Override
        public byte[] f(byte[] pkSeed, Address adrs, byte[] m1, int n) {
            byte[] input = SlhUtils.concat(pkSeed, adrs.getData(), m1);
            return Keccak.shake256(input, n);
        }

        @Override
        public byte[] h(byte[] pkSeed, Address adrs, byte[] m1m2, int n) {
            byte[] input = SlhUtils.concat(pkSeed, adrs.getData(), m1m2);
            return Keccak.shake256(input, n);
        }

        @Override
        public byte[] tl(byte[] pkSeed, Address adrs, byte[] m, int n) {
            byte[] input = SlhUtils.concat(pkSeed, adrs.getData(), m);
            return Keccak.shake256(input, n);
        }
    }

    // ========================================================================
    // SHA2-based hash suite (FIPS 205, Section 11.2)
    // ========================================================================
    class Sha2Hash implements SlhHash {
        private final SlhParams params;
        private final boolean use512; // true for n=32 (256-bit security)

        Sha2Hash(SlhParams params) {
            this.params = params;
            this.use512 = (params.n == 32);
        }

        private byte[] sha256(byte[] input) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                return md.digest(input);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        private byte[] sha512(byte[] input) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                return md.digest(input);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        private byte[] hmacSha256(byte[] key, byte[] data) {
            return hmac("HmacSHA256", key, data);
        }

        private byte[] hmacSha512(byte[] key, byte[] data) {
            return hmac("HmacSHA512", key, data);
        }

        private byte[] hmac(String algo, byte[] key, byte[] data) {
            try {
                Mac mac = Mac.getInstance(algo);
                mac.init(new SecretKeySpec(key, algo));
                return mac.doFinal(data);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        /** MGF1-SHA-256 as defined in RFC 8017. */
        private byte[] mgf1Sha256(byte[] seed, int maskLen) {
            return mgf1(seed, maskLen, "SHA-256", 32);
        }

        /** MGF1-SHA-512 as defined in RFC 8017. */
        private byte[] mgf1Sha512(byte[] seed, int maskLen) {
            return mgf1(seed, maskLen, "SHA-512", 64);
        }

        private byte[] mgf1(byte[] seed, int maskLen, String hashAlgo, int hLen) {
            try {
                byte[] mask = new byte[maskLen];
                int offset = 0;
                int counter = 0;
                MessageDigest md = MessageDigest.getInstance(hashAlgo);
                while (offset < maskLen) {
                    md.reset();
                    md.update(seed);
                    md.update(SlhUtils.toByte(counter, 4));
                    byte[] hash = md.digest();
                    int toCopy = Math.min(hLen, maskLen - offset);
                    System.arraycopy(hash, 0, mask, offset, toCopy);
                    offset += toCopy;
                    counter++;
                }
                return mask;
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * Pad pkSeed to a full SHA-256 block (64 bytes).
         * FIPS 205 Section 11.2: toByte(0, 64 - n) || PK.seed
         */
        private byte[] padBlock256(byte[] pkSeed) {
            byte[] block = new byte[64];
            System.arraycopy(pkSeed, 0, block, 64 - pkSeed.length, pkSeed.length);
            return block;
        }

        /**
         * Pad pkSeed to a full SHA-512 block (128 bytes) for n=32.
         */
        private byte[] padBlock512(byte[] pkSeed) {
            byte[] block = new byte[128];
            System.arraycopy(pkSeed, 0, block, 128 - pkSeed.length, pkSeed.length);
            return block;
        }

        @Override
        public byte[] prf(byte[] pkSeed, byte[] skSeed, Address adrs, int n) {
            // PRF uses compressed ADRS (22 bytes for SHA2)
            byte[] compAdrs = compressAdrs(adrs);
            byte[] block = padBlock256(pkSeed);
            byte[] input = SlhUtils.concat(block, compAdrs, skSeed);
            byte[] hash = sha256(input);
            return SlhUtils.slice(hash, 0, n);
        }

        @Override
        public byte[] prfMsg(byte[] skPrf, byte[] optRand, byte[] msg, int n) {
            byte[] data = SlhUtils.concat(optRand, msg);
            byte[] mac;
            if (use512) {
                mac = hmacSha512(skPrf, data);
            } else {
                mac = hmacSha256(skPrf, data);
            }
            return SlhUtils.slice(mac, 0, n);
        }

        @Override
        public byte[] hMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] msg, int m) {
            byte[] seed = SlhUtils.concat(r, pkSeed, pkRoot, msg);
            if (use512) {
                byte[] hash = sha512(seed);
                return mgf1Sha512(hash, m);
            } else {
                byte[] hash = sha256(seed);
                return mgf1Sha256(hash, m);
            }
        }

        @Override
        public byte[] f(byte[] pkSeed, Address adrs, byte[] m1, int n) {
            byte[] compAdrs = compressAdrs(adrs);
            byte[] block = padBlock256(pkSeed);
            byte[] input = SlhUtils.concat(block, compAdrs, m1);
            byte[] hash = sha256(input);
            return SlhUtils.slice(hash, 0, n);
        }

        @Override
        public byte[] h(byte[] pkSeed, Address adrs, byte[] m1m2, int n) {
            byte[] compAdrs = compressAdrs(adrs);
            if (use512) {
                byte[] block = padBlock512(pkSeed);
                byte[] input = SlhUtils.concat(block, compAdrs, m1m2);
                byte[] hash = sha512(input);
                return SlhUtils.slice(hash, 0, n);
            } else {
                byte[] block = padBlock256(pkSeed);
                byte[] input = SlhUtils.concat(block, compAdrs, m1m2);
                byte[] hash = sha256(input);
                return SlhUtils.slice(hash, 0, n);
            }
        }

        @Override
        public byte[] tl(byte[] pkSeed, Address adrs, byte[] m, int n) {
            byte[] compAdrs = compressAdrs(adrs);
            if (use512) {
                byte[] block = padBlock512(pkSeed);
                byte[] input = SlhUtils.concat(block, compAdrs, m);
                byte[] hash = sha512(input);
                return SlhUtils.slice(hash, 0, n);
            } else {
                byte[] block = padBlock256(pkSeed);
                byte[] input = SlhUtils.concat(block, compAdrs, m);
                byte[] hash = sha256(input);
                return SlhUtils.slice(hash, 0, n);
            }
        }

        /**
         * Compress ADRS to 22 bytes for SHA-2 (FIPS 205, Section 11.2.1).
         * Drops bytes 4..7 (keeping bytes 0..3, 8..31 => 28 bytes,
         * then compress the 4-byte fields at offsets 0,8..15,16..19,20..31
         * to a 22-byte representation).
         */
        private byte[] compressAdrs(Address adrs) {
            byte[] full = adrs.getData();
            byte[] comp = new byte[22];
            // Offset in ADRS -> compressed layout:
            // full[0..3]   -> comp[0..3]   layer (4 bytes -> 1 byte)
            comp[0] = full[3]; // layer fits in 1 byte
            // full[8..15]  -> comp[1..8]   tree address (8 bytes)
            System.arraycopy(full, 8, comp, 1, 8);
            // full[16..19] -> comp[9]      type (4 bytes -> 1 byte)
            comp[9] = full[19];
            // full[20..31] -> comp[10..21]  remaining 12 bytes
            System.arraycopy(full, 20, comp, 10, 12);
            return comp;
        }
    }
}

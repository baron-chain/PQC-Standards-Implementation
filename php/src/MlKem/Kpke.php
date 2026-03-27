<?php

declare(strict_types=1);

namespace PQC\MlKem;

/**
 * K-PKE: The internal public-key encryption scheme used in ML-KEM.
 * FIPS 203 Algorithms 12-14.
 */
final class Kpke
{
    /**
     * K-PKE.KeyGen: Generate encryption key pair.
     * FIPS 203 Algorithm 12.
     *
     * @param string $d 32-byte seed
     * @param int $level 512, 768, or 1024
     * @return array{ek: string, dk: string}
     */
    public static function keyGen(string $d, int $level): array
    {
        $params = Params::get($level);
        $k = $params['k'];
        $eta1 = $params['eta1'];

        // (rho, sigma) = G(d || k)
        $gs = HashFuncs::G($d . chr($k));
        $rho = substr($gs, 0, 32);
        $sigma = substr($gs, 32, 32);

        // Generate matrix A (in NTT domain) from rho
        $aHat = [];
        for ($i = 0; $i < $k; $i++) {
            for ($j = 0; $j < $k; $j++) {
                $aHat[$i][$j] = Sampling::sampleNtt($rho, $i, $j);
            }
        }

        // Sample secret vector s
        $sVec = Sampling::sampleNoiseVec($sigma, $eta1, $k, 0);

        // Sample error vector e
        $eVec = Sampling::sampleNoiseVec($sigma, $eta1, $k, $k);

        // NTT(s), NTT(e)
        $sHat = [];
        $eHat = [];
        for ($i = 0; $i < $k; $i++) {
            $sHat[$i] = Ntt::ntt($sVec[$i]);
            $eHat[$i] = Ntt::ntt($eVec[$i]);
        }

        // t_hat = A_hat * s_hat + e_hat
        $tHat = [];
        for ($i = 0; $i < $k; $i++) {
            $tHat[$i] = $eHat[$i];
            for ($j = 0; $j < $k; $j++) {
                $prod = Ntt::mulNtt($aHat[$i][$j], $sHat[$j]);
                $tHat[$i] = Ntt::polyAdd($tHat[$i], $prod);
            }
        }

        // Encode ek = ByteEncode_12(t_hat) || rho
        $ek = '';
        for ($i = 0; $i < $k; $i++) {
            $ek .= Encode::byteEncode($tHat[$i], 12);
        }
        $ek .= $rho;

        // Encode dk = ByteEncode_12(s_hat)
        $dk = '';
        for ($i = 0; $i < $k; $i++) {
            $dk .= Encode::byteEncode($sHat[$i], 12);
        }

        return ['ek' => $ek, 'dk' => $dk];
    }

    /**
     * K-PKE.Encrypt: Encrypt a 32-byte message.
     * FIPS 203 Algorithm 13.
     *
     * @param string $ek Encryption key
     * @param string $m 32-byte message
     * @param string $r 32-byte randomness
     * @param int $level 512, 768, or 1024
     * @return string Ciphertext
     */
    public static function encrypt(string $ek, string $m, string $r, int $level): string
    {
        $params = Params::get($level);
        $k = $params['k'];
        $eta1 = $params['eta1'];
        $eta2 = $params['eta2'];
        $du = $params['du'];
        $dv = $params['dv'];

        // Decode ek
        $tHat = [];
        for ($i = 0; $i < $k; $i++) {
            $tHat[$i] = Encode::byteDecode(substr($ek, $i * 384, 384), 12);
        }
        $rho = substr($ek, $k * 384, 32);

        // Generate matrix A^T from rho
        $aHat = [];
        for ($i = 0; $i < $k; $i++) {
            for ($j = 0; $j < $k; $j++) {
                $aHat[$i][$j] = Sampling::sampleNtt($rho, $i, $j);
            }
        }

        // Sample vectors r, e1 and scalar e2
        $rVec = Sampling::sampleNoiseVec($r, $eta1, $k, 0);
        $e1Vec = Sampling::sampleNoiseVec($r, $eta2, $k, $k);
        $e2 = Sampling::sampleNoisePoly($r, $eta2, 2 * $k);

        // NTT(r)
        $rHat = [];
        for ($i = 0; $i < $k; $i++) {
            $rHat[$i] = Ntt::ntt($rVec[$i]);
        }

        // u = NTT^{-1}(A^T * r_hat) + e1
        $uVec = [];
        for ($i = 0; $i < $k; $i++) {
            $acc = array_fill(0, 256, 0);
            for ($j = 0; $j < $k; $j++) {
                $prod = Ntt::mulNtt($aHat[$j][$i], $rHat[$j]);
                $acc = Ntt::polyAdd($acc, $prod);
            }
            $uVec[$i] = Ntt::polyAdd(Ntt::invNtt($acc), $e1Vec[$i]);
        }

        // v = NTT^{-1}(t_hat^T * r_hat) + e2 + Decompress_1(m)
        $acc = array_fill(0, 256, 0);
        for ($i = 0; $i < $k; $i++) {
            $prod = Ntt::mulNtt($tHat[$i], $rHat[$i]);
            $acc = Ntt::polyAdd($acc, $prod);
        }
        $v = Ntt::invNtt($acc);
        $v = Ntt::polyAdd($v, $e2);

        // Decode message to polynomial
        $mPoly = Encode::byteDecode($m, 1);
        $mDecomp = Compress::decompressPoly($mPoly, 1);
        $v = Ntt::polyAdd($v, $mDecomp);

        // Compress and encode
        $c1 = '';
        for ($i = 0; $i < $k; $i++) {
            $c1 .= Compress::compressAndEncode($uVec[$i], $du);
        }
        $c2 = Compress::compressAndEncode($v, $dv);

        return $c1 . $c2;
    }

    /**
     * K-PKE.Decrypt: Decrypt a ciphertext.
     * FIPS 203 Algorithm 14.
     *
     * @param string $dk Decryption key
     * @param string $ct Ciphertext
     * @param int $level 512, 768, or 1024
     * @return string 32-byte decrypted message
     */
    public static function decrypt(string $dk, string $ct, int $level): string
    {
        $params = Params::get($level);
        $k = $params['k'];
        $du = $params['du'];
        $dv = $params['dv'];
        $sizes = Params::sizes($level);

        // Decode ciphertext
        $uVec = [];
        $offset = 0;
        for ($i = 0; $i < $k; $i++) {
            $uVec[$i] = Compress::decodeAndDecompress(
                substr($ct, $offset, $sizes['polyCompressedDu']),
                $du
            );
            $offset += $sizes['polyCompressedDu'];
        }
        $v = Compress::decodeAndDecompress(
            substr($ct, $offset, $sizes['polyCompressedDv']),
            $dv
        );

        // Decode secret key
        $sHat = [];
        for ($i = 0; $i < $k; $i++) {
            $sHat[$i] = Encode::byteDecode(substr($dk, $i * 384, 384), 12);
        }

        // m = v - NTT^{-1}(s_hat^T * NTT(u))
        $acc = array_fill(0, 256, 0);
        for ($i = 0; $i < $k; $i++) {
            $uHat = Ntt::ntt($uVec[$i]);
            $prod = Ntt::mulNtt($sHat[$i], $uHat);
            $acc = Ntt::polyAdd($acc, $prod);
        }
        $w = Ntt::invNtt($acc);
        $mPoly = Ntt::polySub($v, $w);

        // Compress to 1 bit and encode
        $mCompressed = Compress::compressPoly($mPoly, 1);
        return Encode::byteEncode($mCompressed, 1);
    }
}

<?php

declare(strict_types=1);

namespace PQC\MlDsa;

/**
 * ML-DSA: Module Lattice-Based Digital Signature Algorithm.
 * FIPS 204.
 */
final class MlDsa
{
    /**
     * ML-DSA.KeyGen: Generate signing/verification key pair.
     *
     * @param int $level 44, 65, or 87
     * @return array{pk: string, sk: string}
     */
    public static function keyGen(int $level): array
    {
        $seed = random_bytes(32);
        return self::keyGenInternal($seed, $level);
    }

    /**
     * Internal deterministic key generation.
     */
    public static function keyGenInternal(string $seed, int $level): array
    {
        $params = DsaParams::get($level);
        $k = $params['k'];
        $l = $params['l'];
        $eta = $params['eta'];

        // Expand seed: (rho, rho', K) = H(seed || k || l)
        $expanded = DsaHash::H($seed . chr($k) . chr($l), 128);
        $rho = substr($expanded, 0, 32);
        $rhoPrime = substr($expanded, 32, 64);
        $K = substr($expanded, 96, 32);

        // Generate matrix A
        $aHat = DsaHash::expandA($rho, $k, $l);

        // Sample secret vectors
        [$s1, $s2] = DsaHash::expandS($rhoPrime, $eta, $k, $l);

        // NTT(s1)
        $s1Hat = [];
        for ($i = 0; $i < $l; $i++) {
            $s1Hat[$i] = DsaNtt::ntt($s1[$i]);
        }

        // t = A * s1 + s2
        $tHat = DsaNtt::matVecMul($aHat, $s1Hat, $k, $l);
        $t = [];
        for ($i = 0; $i < $k; $i++) {
            $t[$i] = DsaNtt::polyAdd(DsaNtt::invNtt($tHat[$i]), $s2[$i]);
        }

        // (t1, t0) = Power2Round(t)
        [$t1, $t0] = Decompose::power2RoundVec($t);

        // Pack public key
        $pk = DsaEncode::packPk($rho, $t1, $k);

        // tr = H(pk)
        $tr = DsaHash::H($pk, 64);

        // Pack secret key
        $sk = DsaEncode::packSk($rho, $K, $tr, $s1, $s2, $t0, $eta, $k, $l);

        return ['pk' => $pk, 'sk' => $sk];
    }

    /**
     * ML-DSA.Sign: Sign a message.
     *
     * @param string $sk Secret key
     * @param string $message Message to sign
     * @param int $level 44, 65, or 87
     * @return string Signature
     */
    public static function sign(string $sk, string $message, int $level): string
    {
        $params = DsaParams::get($level);
        $k = $params['k'];
        $l = $params['l'];
        $eta = $params['eta'];
        $beta = $params['beta'];
        $gamma1 = $params['gamma1'];
        $gamma2 = $params['gamma2'];
        $omega = $params['omega'];
        $tau = $params['tau'];
        $ctildeLen = $params['ctilde_len'];

        // Unpack secret key
        [$rho, $K, $tr, $s1, $s2, $t0] = DsaEncode::unpackSk($sk, $eta, $k, $l);

        // NTT transforms of secret vectors
        $s1Hat = [];
        $s2Hat = [];
        $t0Hat = [];
        for ($i = 0; $i < $l; $i++) {
            $s1Hat[$i] = DsaNtt::ntt($s1[$i]);
        }
        for ($i = 0; $i < $k; $i++) {
            $s2Hat[$i] = DsaNtt::ntt($s2[$i]);
            $t0Hat[$i] = DsaNtt::ntt($t0[$i]);
        }

        // Generate matrix A
        $aHat = DsaHash::expandA($rho, $k, $l);

        // mu = H(tr || M)
        $mu = DsaHash::H($tr . $message, 64);

        // rho' = H(K || mu) (deterministic)
        $rhoPrime = DsaHash::H($K . $mu, 64);

        $kappa = 0;
        while (true) {
            // Sample y from [-gamma1+1, gamma1]
            $y = DsaHash::expandMask($rhoPrime, $kappa, $l, $gamma1);
            $kappa += $l;

            // NTT(y)
            $yHat = [];
            for ($i = 0; $i < $l; $i++) {
                $yHat[$i] = DsaNtt::ntt($y[$i]);
            }

            // w = A * y
            $wHat = DsaNtt::matVecMul($aHat, $yHat, $k, $l);
            $w = [];
            for ($i = 0; $i < $k; $i++) {
                $w[$i] = DsaNtt::invNtt($wHat[$i]);
                for ($j = 0; $j < 256; $j++) {
                    $w[$i][$j] = DsaField::mod($w[$i][$j]);
                }
            }

            // (w1, w0) = Decompose(w)
            $w1 = Decompose::highBitsVec($w, $gamma2);

            // Challenge hash
            $w1Encoded = DsaEncode::encodeW1Vec($w1, $gamma2);
            $ctilde = DsaHash::H($mu . $w1Encoded, $ctildeLen);

            // Sample challenge polynomial
            $c = DsaHash::sampleInBall($ctilde, $tau);
            $cHat = DsaNtt::ntt($c);

            // z = y + c*s1
            $z = [];
            for ($i = 0; $i < $l; $i++) {
                $cs1 = DsaNtt::invNtt(DsaNtt::mulNtt($cHat, $s1Hat[$i]));
                $z[$i] = [];
                for ($j = 0; $j < 256; $j++) {
                    $z[$i][$j] = DsaField::mod($y[$i][$j] + $cs1[$j]);
                }
            }

            // Check ||z||_inf < gamma1 - beta
            if (DsaField::vecNorm($z) >= $gamma1 - $beta) {
                continue;
            }

            // r0 = LowBits(w - c*s2)
            $cs2 = [];
            for ($i = 0; $i < $k; $i++) {
                $cs2[$i] = DsaNtt::invNtt(DsaNtt::mulNtt($cHat, $s2Hat[$i]));
                for ($j = 0; $j < 256; $j++) {
                    $cs2[$i][$j] = DsaField::mod($cs2[$i][$j]);
                }
            }

            $wMinusCs2 = [];
            for ($i = 0; $i < $k; $i++) {
                $wMinusCs2[$i] = [];
                for ($j = 0; $j < 256; $j++) {
                    $wMinusCs2[$i][$j] = DsaField::sub($w[$i][$j], $cs2[$i][$j]);
                }
            }

            $r0 = Decompose::lowBitsVec($wMinusCs2, $gamma2);

            // Check ||r0||_inf < gamma2 - beta
            $r0Norm = 0;
            foreach ($r0 as $poly) {
                foreach ($poly as $c_val) {
                    $centered = $c_val;
                    if ($centered > DsaField::Q / 2) {
                        $centered = $centered - DsaField::Q;
                    }
                    $abs = abs($centered);
                    if ($abs > $r0Norm) {
                        $r0Norm = $abs;
                    }
                }
            }
            if ($r0Norm >= $gamma2 - $beta) {
                continue;
            }

            // Compute hint
            $ct0 = [];
            for ($i = 0; $i < $k; $i++) {
                $ct0[$i] = DsaNtt::invNtt(DsaNtt::mulNtt($cHat, $t0Hat[$i]));
                for ($j = 0; $j < 256; $j++) {
                    $ct0[$i][$j] = DsaField::mod($ct0[$i][$j]);
                }
            }

            // Check ||ct0||_inf < gamma2
            if (DsaField::vecNorm($ct0) >= $gamma2) {
                continue;
            }

            // Compute w - cs2 + ct0 for hint
            $wcs2ct0 = [];
            for ($i = 0; $i < $k; $i++) {
                $wcs2ct0[$i] = [];
                for ($j = 0; $j < 256; $j++) {
                    $wcs2ct0[$i][$j] = DsaField::add($wMinusCs2[$i][$j], $ct0[$i][$j]);
                }
            }

            // Negate ct0 for hint computation
            $negCt0 = [];
            for ($i = 0; $i < $k; $i++) {
                $negCt0[$i] = [];
                for ($j = 0; $j < 256; $j++) {
                    $negCt0[$i][$j] = DsaField::mod(-$ct0[$i][$j]);
                }
            }

            [$h, $numOnes] = Decompose::makeHintVec($negCt0, $wcs2ct0, $gamma2, $k);

            if ($numOnes > $omega) {
                continue;
            }

            // Encode signature: ctilde || z || h
            $sig = $ctilde;
            for ($i = 0; $i < $l; $i++) {
                $sig .= DsaEncode::encodeZ($z[$i], $gamma1);
            }
            $sig .= DsaEncode::encodeHint($h, $omega, $k);

            return $sig;
        }
    }

    /**
     * ML-DSA.Verify: Verify a signature.
     *
     * @param string $pk Public key
     * @param string $message Message
     * @param string $sig Signature
     * @param int $level 44, 65, or 87
     * @return bool True if valid
     */
    public static function verify(string $pk, string $message, string $sig, int $level): bool
    {
        $params = DsaParams::get($level);
        $k = $params['k'];
        $l = $params['l'];
        $beta = $params['beta'];
        $gamma1 = $params['gamma1'];
        $gamma2 = $params['gamma2'];
        $omega = $params['omega'];
        $tau = $params['tau'];
        $ctildeLen = $params['ctilde_len'];

        // Unpack public key
        [$rho, $t1] = DsaEncode::unpackPk($pk, $k);

        // Decode signature
        $offset = 0;
        $ctilde = substr($sig, $offset, $ctildeLen);
        $offset += $ctildeLen;

        $gamma1Bytes = ($gamma1 === (1 << 17)) ? 576 : 640; // 256*18/8 or 256*20/8
        $z = [];
        for ($i = 0; $i < $l; $i++) {
            $z[$i] = DsaEncode::decodeZ(substr($sig, $offset, $gamma1Bytes), $gamma1);
            $offset += $gamma1Bytes;
        }

        $h = DsaEncode::decodeHint(substr($sig, $offset, $omega + $k), $omega, $k);

        // Check ||z||_inf < gamma1 - beta
        if (DsaField::vecNorm($z) >= $gamma1 - $beta) {
            return false;
        }

        // Generate A
        $aHat = DsaHash::expandA($rho, $k, $l);

        // tr = H(pk)
        $tr = DsaHash::H($pk, 64);

        // mu = H(tr || M)
        $mu = DsaHash::H($tr . $message, 64);

        // Sample challenge
        $c = DsaHash::sampleInBall($ctilde, $tau);
        $cHat = DsaNtt::ntt($c);

        // Compute Az - ct1*2^d
        $zHat = [];
        for ($i = 0; $i < $l; $i++) {
            $zHat[$i] = DsaNtt::ntt($z[$i]);
        }

        $azHat = DsaNtt::matVecMul($aHat, $zHat, $k, $l);

        // t1 * 2^d
        $t1Shifted = [];
        for ($i = 0; $i < $k; $i++) {
            $t1Shifted[$i] = [];
            for ($j = 0; $j < 256; $j++) {
                $t1Shifted[$i][$j] = DsaField::mod($t1[$i][$j] << DsaParams::D);
            }
        }

        // ct1_2d = NTT(c) * NTT(t1*2^d)
        $wPrime = [];
        for ($i = 0; $i < $k; $i++) {
            $t1sHat = DsaNtt::ntt($t1Shifted[$i]);
            $ct1 = DsaNtt::mulNtt($cHat, $t1sHat);
            $azI = DsaNtt::invNtt($azHat[$i]);
            $ct1I = DsaNtt::invNtt($ct1);
            $wPrime[$i] = [];
            for ($j = 0; $j < 256; $j++) {
                $wPrime[$i][$j] = DsaField::sub($azI[$j], $ct1I[$j]);
            }
        }

        // UseHint to recover w1'
        $w1Prime = Decompose::useHintVec($h, $wPrime, $gamma2, $k);

        // Recompute challenge hash
        $w1Encoded = DsaEncode::encodeW1Vec($w1Prime, $gamma2);
        $ctildePrime = DsaHash::H($mu . $w1Encoded, $ctildeLen);

        return hash_equals($ctilde, $ctildePrime);
    }
}

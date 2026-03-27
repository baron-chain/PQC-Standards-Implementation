<?php

declare(strict_types=1);

namespace PQC\MlDsa;

/**
 * Encoding/decoding functions for ML-DSA.
 */
final class DsaEncode
{
    /**
     * Encode polynomial t1 (10-bit coefficients).
     */
    public static function encodeT1(array $poly): string
    {
        $bytes = '';
        for ($i = 0; $i < 256; $i += 4) {
            $a = $poly[$i] & 0x3FF;
            $b = $poly[$i + 1] & 0x3FF;
            $c = $poly[$i + 2] & 0x3FF;
            $d = $poly[$i + 3] & 0x3FF;

            $bytes .= chr($a & 0xFF);
            $bytes .= chr((($a >> 8) | ($b << 2)) & 0xFF);
            $bytes .= chr((($b >> 6) | ($c << 4)) & 0xFF);
            $bytes .= chr((($c >> 4) | ($d << 6)) & 0xFF);
            $bytes .= chr(($d >> 2) & 0xFF);
        }
        return $bytes;
    }

    /**
     * Decode polynomial t1.
     */
    public static function decodeT1(string $bytes): array
    {
        $poly = [];
        for ($i = 0; $i < 64; $i++) {
            $offset = $i * 5;
            $b0 = ord($bytes[$offset]);
            $b1 = ord($bytes[$offset + 1]);
            $b2 = ord($bytes[$offset + 2]);
            $b3 = ord($bytes[$offset + 3]);
            $b4 = ord($bytes[$offset + 4]);

            $poly[] = ($b0 | (($b1 & 0x03) << 8)) & 0x3FF;
            $poly[] = (($b1 >> 2) | (($b2 & 0x0F) << 6)) & 0x3FF;
            $poly[] = (($b2 >> 4) | (($b3 & 0x3F) << 4)) & 0x3FF;
            $poly[] = (($b3 >> 6) | ($b4 << 2)) & 0x3FF;
        }
        return $poly;
    }

    /**
     * Encode vector of t1 polynomials.
     */
    public static function encodeT1Vec(array $vec): string
    {
        $bytes = '';
        foreach ($vec as $poly) {
            $bytes .= self::encodeT1($poly);
        }
        return $bytes;
    }

    /**
     * Decode vector of t1 polynomials.
     */
    public static function decodeT1Vec(string $bytes, int $k): array
    {
        $vec = [];
        $polyLen = 320; // 256 * 10 / 8
        for ($i = 0; $i < $k; $i++) {
            $vec[$i] = self::decodeT1(substr($bytes, $i * $polyLen, $polyLen));
        }
        return $vec;
    }

    /**
     * Encode eta-bounded polynomial.
     */
    public static function encodeEta(array $poly, int $eta): string
    {
        if ($eta === 2) {
            return self::encodeEta2($poly);
        }
        return self::encodeEta4($poly);
    }

    private static function encodeEta2(array $poly): string
    {
        // 3 bits per coefficient
        $bytes = '';
        for ($i = 0; $i < 256; $i += 8) {
            $vals = [];
            for ($j = 0; $j < 8; $j++) {
                $v = DsaField::centered($poly[$i + $j]);
                $vals[$j] = 2 - $v; // Map [-2,2] to [0,4]
            }
            // Pack 8 values of 3 bits into 3 bytes
            $bytes .= chr($vals[0] | ($vals[1] << 3) | (($vals[2] & 0x03) << 6));
            $bytes .= chr(($vals[2] >> 2) | ($vals[3] << 1) | ($vals[4] << 4) | (($vals[5] & 0x01) << 7));
            $bytes .= chr(($vals[5] >> 1) | ($vals[6] << 2) | ($vals[7] << 5));
        }
        return $bytes;
    }

    private static function encodeEta4(array $poly): string
    {
        // 4 bits per coefficient
        $bytes = '';
        for ($i = 0; $i < 256; $i += 2) {
            $a = 4 - DsaField::centered($poly[$i]);
            $b = 4 - DsaField::centered($poly[$i + 1]);
            $bytes .= chr(($a & 0x0F) | (($b & 0x0F) << 4));
        }
        return $bytes;
    }

    /**
     * Decode eta-bounded polynomial.
     */
    public static function decodeEta(string $bytes, int $eta): array
    {
        if ($eta === 2) {
            return self::decodeEta2($bytes);
        }
        return self::decodeEta4($bytes);
    }

    private static function decodeEta2(string $bytes): array
    {
        $poly = [];
        for ($i = 0; $i < 96; $i += 3) {
            $b0 = ord($bytes[$i]);
            $b1 = ord($bytes[$i + 1]);
            $b2 = ord($bytes[$i + 2]);

            $poly[] = DsaField::mod(2 - ($b0 & 0x07));
            $poly[] = DsaField::mod(2 - (($b0 >> 3) & 0x07));
            $poly[] = DsaField::mod(2 - (($b0 >> 6) | (($b1 & 0x01) << 2)));
            $poly[] = DsaField::mod(2 - (($b1 >> 1) & 0x07));
            $poly[] = DsaField::mod(2 - (($b1 >> 4) & 0x07));
            $poly[] = DsaField::mod(2 - (($b1 >> 7) | (($b2 & 0x03) << 1)));
            $poly[] = DsaField::mod(2 - (($b2 >> 2) & 0x07));
            $poly[] = DsaField::mod(2 - (($b2 >> 5) & 0x07));
        }
        return $poly;
    }

    private static function decodeEta4(string $bytes): array
    {
        $poly = [];
        for ($i = 0; $i < 128; $i++) {
            $b = ord($bytes[$i]);
            $poly[] = DsaField::mod(4 - ($b & 0x0F));
            $poly[] = DsaField::mod(4 - ($b >> 4));
        }
        return $poly;
    }

    /**
     * Encode z polynomial (gamma1-bounded) for signature.
     */
    public static function encodeZ(array $poly, int $gamma1): string
    {
        if ($gamma1 === (1 << 17)) {
            return self::encodeZ17($poly);
        }
        return self::encodeZ19($poly);
    }

    private static function encodeZ17(array $poly): string
    {
        // 18 bits per coefficient, 4 coefficients per 9 bytes
        $bytes = '';
        for ($i = 0; $i < 256; $i += 4) {
            $vals = [];
            for ($j = 0; $j < 4; $j++) {
                $vals[$j] = ((1 << 17) - DsaField::centered($poly[$i + $j])) & 0x3FFFF;
            }
            $bytes .= chr($vals[0] & 0xFF);
            $bytes .= chr(($vals[0] >> 8) & 0xFF);
            $bytes .= chr((($vals[0] >> 16) | ($vals[1] << 2)) & 0xFF);
            $bytes .= chr(($vals[1] >> 6) & 0xFF);
            $bytes .= chr((($vals[1] >> 14) | ($vals[2] << 4)) & 0xFF);
            $bytes .= chr(($vals[2] >> 4) & 0xFF);
            $bytes .= chr((($vals[2] >> 12) | ($vals[3] << 6)) & 0xFF);
            $bytes .= chr(($vals[3] >> 2) & 0xFF);
            $bytes .= chr(($vals[3] >> 10) & 0xFF);
        }
        return $bytes;
    }

    private static function encodeZ19(array $poly): string
    {
        // 20 bits per coefficient, 2 coefficients per 5 bytes
        $bytes = '';
        for ($i = 0; $i < 256; $i += 2) {
            $a = ((1 << 19) - DsaField::centered($poly[$i])) & 0xFFFFF;
            $b = ((1 << 19) - DsaField::centered($poly[$i + 1])) & 0xFFFFF;

            $bytes .= chr($a & 0xFF);
            $bytes .= chr(($a >> 8) & 0xFF);
            $bytes .= chr((($a >> 16) | ($b << 4)) & 0xFF);
            $bytes .= chr(($b >> 4) & 0xFF);
            $bytes .= chr(($b >> 12) & 0xFF);
        }
        return $bytes;
    }

    /**
     * Decode z polynomial.
     */
    public static function decodeZ(string $bytes, int $gamma1): array
    {
        if ($gamma1 === (1 << 17)) {
            return self::decodeZ17($bytes);
        }
        return self::decodeZ19($bytes);
    }

    private static function decodeZ17(string $bytes): array
    {
        $poly = [];
        for ($i = 0; $i < 64; $i++) {
            $offset = $i * 9;
            $b = [];
            for ($j = 0; $j < 9; $j++) {
                $b[$j] = ord($bytes[$offset + $j]);
            }

            $val0 = ($b[0] | ($b[1] << 8) | (($b[2] & 0x03) << 16)) & 0x3FFFF;
            $val1 = (($b[2] >> 2) | ($b[3] << 6) | (($b[4] & 0x0F) << 14)) & 0x3FFFF;
            $val2 = (($b[4] >> 4) | ($b[5] << 4) | (($b[6] & 0x3F) << 12)) & 0x3FFFF;
            $val3 = (($b[6] >> 6) | ($b[7] << 2) | ($b[8] << 10)) & 0x3FFFF;

            $poly[] = DsaField::mod((1 << 17) - $val0);
            $poly[] = DsaField::mod((1 << 17) - $val1);
            $poly[] = DsaField::mod((1 << 17) - $val2);
            $poly[] = DsaField::mod((1 << 17) - $val3);
        }
        return $poly;
    }

    private static function decodeZ19(string $bytes): array
    {
        $poly = [];
        for ($i = 0; $i < 128; $i++) {
            $offset = $i * 5;
            $b0 = ord($bytes[$offset]);
            $b1 = ord($bytes[$offset + 1]);
            $b2 = ord($bytes[$offset + 2]);
            $b3 = ord($bytes[$offset + 3]);
            $b4 = ord($bytes[$offset + 4]);

            $val0 = ($b0 | ($b1 << 8) | (($b2 & 0x0F) << 16)) & 0xFFFFF;
            $val1 = (($b2 >> 4) | ($b3 << 4) | ($b4 << 12)) & 0xFFFFF;

            $poly[] = DsaField::mod((1 << 19) - $val0);
            $poly[] = DsaField::mod((1 << 19) - $val1);
        }
        return $poly;
    }

    /**
     * Encode hint vector h.
     */
    public static function encodeHint(array $h, int $omega, int $k): string
    {
        $bytes = str_repeat("\x00", $omega + $k);
        $idx = 0;
        for ($i = 0; $i < $k; $i++) {
            for ($j = 0; $j < 256; $j++) {
                if ($h[$i][$j] === 1) {
                    $bytes[$idx++] = chr($j);
                }
            }
            $bytes[$omega + $i] = chr($idx);
        }
        return $bytes;
    }

    /**
     * Decode hint vector h.
     */
    public static function decodeHint(string $bytes, int $omega, int $k): array
    {
        $h = [];
        for ($i = 0; $i < $k; $i++) {
            $h[$i] = array_fill(0, 256, 0);
        }

        $prev = 0;
        for ($i = 0; $i < $k; $i++) {
            $limit = ord($bytes[$omega + $i]);
            for ($j = $prev; $j < $limit; $j++) {
                $h[$i][ord($bytes[$j])] = 1;
            }
            $prev = $limit;
        }

        return $h;
    }

    /**
     * Pack public key: rho || t1_encoded.
     */
    public static function packPk(string $rho, array $t1, int $k): string
    {
        return $rho . self::encodeT1Vec($t1);
    }

    /**
     * Unpack public key.
     */
    public static function unpackPk(string $pk, int $k): array
    {
        $rho = substr($pk, 0, 32);
        $t1 = self::decodeT1Vec(substr($pk, 32), $k);
        return [$rho, $t1];
    }

    /**
     * Pack secret key.
     */
    public static function packSk(string $rho, string $K, string $tr, array $s1, array $s2, array $t0, int $eta, int $k, int $l): string
    {
        $sk = $rho . $K . $tr;

        // Encode s1
        $etaBytes = ($eta === 2) ? 96 : 128;
        foreach ($s1 as $poly) {
            $sk .= self::encodeEta($poly, $eta);
        }

        // Encode s2
        foreach ($s2 as $poly) {
            $sk .= self::encodeEta($poly, $eta);
        }

        // Encode t0 (13-bit coefficients)
        foreach ($t0 as $poly) {
            $sk .= self::encodeT0($poly);
        }

        return $sk;
    }

    /**
     * Unpack secret key.
     */
    public static function unpackSk(string $sk, int $eta, int $k, int $l): array
    {
        $offset = 0;
        $rho = substr($sk, $offset, 32); $offset += 32;
        $K = substr($sk, $offset, 32); $offset += 32;
        $tr = substr($sk, $offset, 64); $offset += 64;

        $etaBytes = ($eta === 2) ? 96 : 128;

        $s1 = [];
        for ($i = 0; $i < $l; $i++) {
            $s1[$i] = self::decodeEta(substr($sk, $offset, $etaBytes), $eta);
            $offset += $etaBytes;
        }

        $s2 = [];
        for ($i = 0; $i < $k; $i++) {
            $s2[$i] = self::decodeEta(substr($sk, $offset, $etaBytes), $eta);
            $offset += $etaBytes;
        }

        $t0 = [];
        for ($i = 0; $i < $k; $i++) {
            $t0[$i] = self::decodeT0(substr($sk, $offset, 416));
            $offset += 416;
        }

        return [$rho, $K, $tr, $s1, $s2, $t0];
    }

    /**
     * Encode t0 polynomial (13-bit coefficients).
     */
    public static function encodeT0(array $poly): string
    {
        $bytes = '';
        $d = DsaParams::D; // 13
        $halfD = 1 << ($d - 1); // 4096

        for ($i = 0; $i < 256; $i += 8) {
            $vals = [];
            for ($j = 0; $j < 8; $j++) {
                $v = DsaField::centered($poly[$i + $j]);
                $vals[$j] = ($halfD - $v) & 0x1FFF;
            }
            // Pack 8 x 13 bits = 104 bits = 13 bytes
            $bytes .= chr($vals[0] & 0xFF);
            $bytes .= chr((($vals[0] >> 8) | ($vals[1] << 5)) & 0xFF);
            $bytes .= chr(($vals[1] >> 3) & 0xFF);
            $bytes .= chr((($vals[1] >> 11) | ($vals[2] << 2)) & 0xFF);
            $bytes .= chr((($vals[2] >> 6) | ($vals[3] << 7)) & 0xFF);
            $bytes .= chr(($vals[3] >> 1) & 0xFF);
            $bytes .= chr((($vals[3] >> 9) | ($vals[4] << 4)) & 0xFF);
            $bytes .= chr(($vals[4] >> 4) & 0xFF);
            $bytes .= chr((($vals[4] >> 12) | ($vals[5] << 1)) & 0xFF);
            $bytes .= chr((($vals[5] >> 7) | ($vals[6] << 6)) & 0xFF);
            $bytes .= chr(($vals[6] >> 2) & 0xFF);
            $bytes .= chr((($vals[6] >> 10) | ($vals[7] << 3)) & 0xFF);
            $bytes .= chr(($vals[7] >> 5) & 0xFF);
        }
        return $bytes;
    }

    /**
     * Decode t0 polynomial.
     */
    public static function decodeT0(string $bytes): array
    {
        $poly = [];
        $halfD = 1 << (DsaParams::D - 1); // 4096

        for ($i = 0; $i < 32; $i++) {
            $offset = $i * 13;
            $b = [];
            for ($j = 0; $j < 13; $j++) {
                $b[$j] = ord($bytes[$offset + $j]);
            }

            $poly[] = DsaField::mod($halfD - (($b[0] | (($b[1] & 0x1F) << 8)) & 0x1FFF));
            $poly[] = DsaField::mod($halfD - ((($b[1] >> 5) | ($b[2] << 3) | (($b[3] & 0x03) << 11)) & 0x1FFF));
            $poly[] = DsaField::mod($halfD - ((($b[3] >> 2) | (($b[4] & 0x7F) << 6)) & 0x1FFF));
            $poly[] = DsaField::mod($halfD - ((($b[4] >> 7) | ($b[5] << 1) | (($b[6] & 0x0F) << 9)) & 0x1FFF));
            $poly[] = DsaField::mod($halfD - ((($b[6] >> 4) | ($b[7] << 4) | (($b[8] & 0x01) << 12)) & 0x1FFF));
            $poly[] = DsaField::mod($halfD - ((($b[8] >> 1) | (($b[9] & 0x3F) << 7)) & 0x1FFF));
            $poly[] = DsaField::mod($halfD - ((($b[9] >> 6) | ($b[10] << 2) | (($b[11] & 0x07) << 10)) & 0x1FFF));
            $poly[] = DsaField::mod($halfD - ((($b[11] >> 3) | ($b[12] << 5)) & 0x1FFF));
        }
        return $poly;
    }

    /**
     * Encode w1 polynomial for signature hashing.
     */
    public static function encodeW1(array $poly, int $gamma2): string
    {
        if ($gamma2 === intdiv(DsaField::Q - 1, 88)) {
            // 6 bits per coefficient
            $bytes = '';
            for ($i = 0; $i < 256; $i += 4) {
                $a = $poly[$i] & 0x3F;
                $b = $poly[$i + 1] & 0x3F;
                $c = $poly[$i + 2] & 0x3F;
                $d = $poly[$i + 3] & 0x3F;

                $bytes .= chr($a | (($b & 0x03) << 6));
                $bytes .= chr(($b >> 2) | (($c & 0x0F) << 4));
                $bytes .= chr(($c >> 4) | ($d << 2));
            }
            return $bytes;
        }

        // 4 bits per coefficient (gamma2 = (q-1)/32)
        $bytes = '';
        for ($i = 0; $i < 256; $i += 2) {
            $a = $poly[$i] & 0x0F;
            $b = $poly[$i + 1] & 0x0F;
            $bytes .= chr($a | ($b << 4));
        }
        return $bytes;
    }

    /**
     * Encode w1 vector.
     */
    public static function encodeW1Vec(array $vec, int $gamma2): string
    {
        $bytes = '';
        foreach ($vec as $poly) {
            $bytes .= self::encodeW1($poly, $gamma2);
        }
        return $bytes;
    }
}

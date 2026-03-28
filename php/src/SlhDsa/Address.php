<?php

declare(strict_types=1);

namespace PQC\SlhDsa;

/**
 * ADRS (Address) structure for SLH-DSA.
 * 32-byte address used to domain-separate hash calls.
 */
final class Address
{
    // Address types
    public const WOTS_HASH = 0;
    public const WOTS_PK = 1;
    public const TREE = 2;
    public const FORS_TREE = 3;
    public const FORS_ROOTS = 4;
    public const WOTS_PRF = 5;
    public const FORS_PRF = 6;

    private string $data;

    public function __construct()
    {
        $this->data = str_repeat("\x00", 32);
    }

    public function copy(): self
    {
        $new = new self();
        $new->data = $this->data;
        return $new;
    }

    public function toBytes(): string
    {
        return $this->data;
    }

    /**
     * Set layer address (bytes 0-3).
     */
    public function setLayerAddress(int $layer): self
    {
        $this->setWord(0, $layer);
        return $this;
    }

    /**
     * Set tree address (bytes 4-15).
     */
    public function setTreeAddress(int $tree): self
    {
        // FIPS 205 Figure 2: bytes 4-7 zero, bytes 8-15 hold uint64 big-endian
        $this->data[4]  = "\x00";
        $this->data[5]  = "\x00";
        $this->data[6]  = "\x00";
        $this->data[7]  = "\x00";
        $this->data[8]  = chr(($tree >> 56) & 0xFF);
        $this->data[9]  = chr(($tree >> 48) & 0xFF);
        $this->data[10] = chr(($tree >> 40) & 0xFF);
        $this->data[11] = chr(($tree >> 32) & 0xFF);
        $this->data[12] = chr(($tree >> 24) & 0xFF);
        $this->data[13] = chr(($tree >> 16) & 0xFF);
        $this->data[14] = chr(($tree >> 8) & 0xFF);
        $this->data[15] = chr($tree & 0xFF);
        return $this;
    }

    /**
     * Set address type (bytes 16-19).
     */
    public function setType(int $type): self
    {
        $this->setWord(16, $type);
        // Reset subsequent fields when type changes
        $this->data[20] = "\x00";
        $this->data[21] = "\x00";
        $this->data[22] = "\x00";
        $this->data[23] = "\x00";
        $this->data[24] = "\x00";
        $this->data[25] = "\x00";
        $this->data[26] = "\x00";
        $this->data[27] = "\x00";
        $this->data[28] = "\x00";
        $this->data[29] = "\x00";
        $this->data[30] = "\x00";
        $this->data[31] = "\x00";
        return $this;
    }

    /**
     * Set keypair address (bytes 20-23).
     */
    public function setKeyPairAddress(int $kp): self
    {
        $this->setWord(20, $kp);
        return $this;
    }

    /**
     * Set chain address (bytes 24-27).
     */
    public function setChainAddress(int $chain): self
    {
        $this->setWord(24, $chain);
        return $this;
    }

    /**
     * Set hash address (bytes 28-31).
     */
    public function setHashAddress(int $hash): self
    {
        $this->setWord(28, $hash);
        return $this;
    }

    /**
     * Set tree height (bytes 24-27).
     */
    public function setTreeHeight(int $height): self
    {
        $this->setWord(24, $height);
        return $this;
    }

    /**
     * Set tree index (bytes 28-31).
     */
    public function setTreeIndex(int $index): self
    {
        $this->setWord(28, $index);
        return $this;
    }

    /**
     * Get keypair address.
     */
    public function getKeyPairAddress(): int
    {
        return $this->getWord(20);
    }

    /**
     * Set 4 bytes at offset as big-endian 32-bit integer.
     */
    private function setWord(int $offset, int $value): void
    {
        $this->data[$offset] = chr(($value >> 24) & 0xFF);
        $this->data[$offset + 1] = chr(($value >> 16) & 0xFF);
        $this->data[$offset + 2] = chr(($value >> 8) & 0xFF);
        $this->data[$offset + 3] = chr($value & 0xFF);
    }

    /**
     * Get 4-byte big-endian value.
     */
    private function getWord(int $offset): int
    {
        return (ord($this->data[$offset]) << 24) |
               (ord($this->data[$offset + 1]) << 16) |
               (ord($this->data[$offset + 2]) << 8) |
               ord($this->data[$offset + 3]);
    }
}

package com.pqc.slhdsa;

/**
 * ADRS (Address) structure for SLH-DSA per FIPS 205 Section 4.2.
 * A 32-byte address encoding with 7 types.
 */
public final class Address {

    // Address types (FIPS 205 Table 2)
    public static final int WOTS_HASH    = 0;
    public static final int WOTS_PK      = 1;
    public static final int TREE         = 2;
    public static final int FORS_TREE    = 3;
    public static final int FORS_ROOTS   = 4;
    public static final int WOTS_PRF     = 5;
    public static final int FORS_PRF     = 6;

    // Internal 32-byte buffer
    // Layout (byte offsets):
    //  0..3   layer address
    //  4..15  tree address (8 bytes used, right-aligned in 12 bytes)
    //  16..19 type
    //  20..31 type-specific fields:
    //    For WOTS: 20..23 = keypair address, 24..27 = chain address, 28..31 = hash address
    //    For TREE: 20..23 = padding(0), 24..27 = padding(0), 28..31 = tree height/index
    //    For FORS: 20..23 = keypair address, 24..27 = tree height, 28..31 = tree index
    private final byte[] data;

    public Address() {
        this.data = new byte[32];
    }

    public Address(Address other) {
        this.data = other.data.clone();
    }

    public byte[] toBytes() {
        return data.clone();
    }

    /** Get the raw data array (for efficient hashing). */
    public byte[] getData() {
        return data;
    }

    // ---- Layer address (bytes 0..3) ----
    public Address setLayerAddress(int layer) {
        putInt(data, 0, layer);
        return this;
    }

    // ---- Tree address (bytes 4..15, 64-bit value right-aligned) ----
    public Address setTreeAddress(long tree) {
        // bytes 4..7 = 0 (padding), bytes 8..15 = tree (big-endian)
        putInt(data, 4, 0);
        data[8]  = (byte)(tree >> 56);
        data[9]  = (byte)(tree >> 48);
        data[10] = (byte)(tree >> 40);
        data[11] = (byte)(tree >> 32);
        data[12] = (byte)(tree >> 24);
        data[13] = (byte)(tree >> 16);
        data[14] = (byte)(tree >> 8);
        data[15] = (byte)(tree);
        return this;
    }

    // ---- Type field (bytes 16..19) ----
    public Address setType(int type) {
        putInt(data, 16, type);
        // Clear type-specific fields (bytes 20..31) when type changes
        for (int i = 20; i < 32; i++) {
            data[i] = 0;
        }
        return this;
    }

    // ---- Keypair address (bytes 20..23) ----
    public Address setKeyPairAddress(int kp) {
        putInt(data, 20, kp);
        return this;
    }

    public int getKeyPairAddress() {
        return getInt(data, 20);
    }

    // ---- Chain address (bytes 24..27) ----
    public Address setChainAddress(int chain) {
        putInt(data, 24, chain);
        return this;
    }

    // ---- Hash address (bytes 28..31) ----
    public Address setHashAddress(int hash) {
        putInt(data, 28, hash);
        return this;
    }

    // ---- Tree height (bytes 24..27) ----
    public Address setTreeHeight(int height) {
        putInt(data, 24, height);
        return this;
    }

    // ---- Tree index (bytes 28..31) ----
    public Address setTreeIndex(int index) {
        putInt(data, 28, index);
        return this;
    }

    // --- Helper: 4-byte big-endian put/get ---
    private static void putInt(byte[] buf, int offset, int val) {
        buf[offset]     = (byte)(val >> 24);
        buf[offset + 1] = (byte)(val >> 16);
        buf[offset + 2] = (byte)(val >> 8);
        buf[offset + 3] = (byte)(val);
    }

    private static int getInt(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 24)
             | ((buf[offset + 1] & 0xFF) << 16)
             | ((buf[offset + 2] & 0xFF) << 8)
             | (buf[offset + 3] & 0xFF);
    }
}

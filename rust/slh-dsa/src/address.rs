//! SLH-DSA (FIPS 205) address structure (ADRS).
//!
//! ADRS is a 32-byte structure used as a domain separator (tweak) in hash
//! computations. Fields are stored in big-endian byte order.

use alloc::vec::Vec;

/// Address types used in SLH-DSA hash computations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AddressType {
    /// WOTS+ hash address (chain hashing).
    WotsHash = 0,
    /// WOTS+ public key compression.
    WotsPk = 1,
    /// Hash tree (XMSS internal node).
    Tree = 2,
    /// FORS tree node.
    ForsTree = 3,
    /// FORS roots compression.
    ForsRoots = 4,
    /// WOTS+ PRF key generation.
    WotsPrf = 5,
    /// FORS PRF key generation.
    ForsPrf = 6,
}

/// A 32-byte address structure used as a tweak in SLH-DSA hash functions.
///
/// Layout (all fields big-endian):
/// - bytes\[0..4\]:   layer address
/// - bytes\[4..16\]:  tree address (12 bytes, supporting large tree indices)
/// - bytes\[16..20\]: address type
/// - bytes\[20..24\]: key pair address (WOTS/FORS key index within a tree)
/// - bytes\[24..28\]: chain address (WOTS) or tree height (XMSS/FORS)
/// - bytes\[28..32\]: hash address (WOTS) or tree index (XMSS/FORS)
#[derive(Clone)]
pub struct Address {
    bytes: [u8; 32],
}

impl Address {
    /// Create a new zero-initialized address.
    pub fn new() -> Self {
        Self { bytes: [0u8; 32] }
    }

    /// Return a reference to the raw 32-byte representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Set the layer address (bytes 0..4).
    pub fn set_layer_address(&mut self, layer: u32) {
        self.bytes[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    /// Set the tree address (bytes 4..16) from a 64-bit value.
    ///
    /// The 64-bit tree index is placed in the lower 8 bytes of the 12-byte
    /// field (bytes 8..16), with the upper 4 bytes (bytes 4..8) zeroed.
    pub fn set_tree_address(&mut self, tree: u64) {
        self.bytes[4..8].copy_from_slice(&[0u8; 4]);
        self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// Set the address type (bytes 16..20).
    pub fn set_type(&mut self, addr_type: AddressType) {
        let val = addr_type as u32;
        self.bytes[16..20].copy_from_slice(&val.to_be_bytes());
        // Per FIPS 205: when setting the type, the subsequent fields
        // (bytes 20..32) are zeroed.
        self.bytes[20..32].copy_from_slice(&[0u8; 12]);
    }

    /// Set the key pair address (bytes 20..24).
    pub fn set_key_pair_address(&mut self, kp: u32) {
        self.bytes[20..24].copy_from_slice(&kp.to_be_bytes());
    }

    /// Get the key pair address (bytes 20..24).
    pub fn get_key_pair_address(&self) -> u32 {
        u32::from_be_bytes([self.bytes[20], self.bytes[21], self.bytes[22], self.bytes[23]])
    }

    /// Set the chain address (bytes 24..28). Used in WOTS+ chain hashing.
    pub fn set_chain_address(&mut self, chain: u32) {
        self.bytes[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    /// Set the tree height (bytes 24..28). Used in XMSS/FORS tree hashing.
    pub fn set_tree_height(&mut self, height: u32) {
        self.bytes[24..28].copy_from_slice(&height.to_be_bytes());
    }

    /// Set the hash address (bytes 28..32). Used in WOTS+ chain hashing.
    pub fn set_hash_address(&mut self, hash: u32) {
        self.bytes[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    /// Set the tree index (bytes 28..32). Used in XMSS/FORS tree hashing.
    pub fn set_tree_index(&mut self, index: u32) {
        self.bytes[28..32].copy_from_slice(&index.to_be_bytes());
    }

    /// Get the tree index (bytes 28..32).
    pub fn get_tree_index(&self) -> u32 {
        u32::from_be_bytes([self.bytes[28], self.bytes[29], self.bytes[30], self.bytes[31]])
    }

    /// Return a copy of this address.
    pub fn copy(&self) -> Self {
        self.clone()
    }

    /// Return the address as a `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Address")
            .field("bytes", &hex_fmt(&self.bytes))
            .finish()
    }
}

/// Helper to format bytes as hex for Debug output.
fn hex_fmt(bytes: &[u8]) -> alloc::string::String {
    use alloc::format;
    let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_zeroed() {
        let adrs = Address::new();
        assert_eq!(adrs.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_set_layer_address() {
        let mut adrs = Address::new();
        adrs.set_layer_address(5);
        assert_eq!(&adrs.as_bytes()[0..4], &[0, 0, 0, 5]);
        adrs.set_layer_address(0x01020304);
        assert_eq!(&adrs.as_bytes()[0..4], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_set_tree_address() {
        let mut adrs = Address::new();
        adrs.set_tree_address(0x0102030405060708);
        // Upper 4 bytes of the 12-byte field are zero.
        assert_eq!(&adrs.as_bytes()[4..8], &[0, 0, 0, 0]);
        assert_eq!(
            &adrs.as_bytes()[8..16],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_set_type_clears_trailing() {
        let mut adrs = Address::new();
        // Set some fields first.
        adrs.set_key_pair_address(42);
        adrs.set_chain_address(7);
        adrs.set_hash_address(99);
        // Now set type; this must zero bytes 20..32.
        adrs.set_type(AddressType::WotsHash);
        assert_eq!(&adrs.as_bytes()[16..20], &[0, 0, 0, 0]);
        assert_eq!(&adrs.as_bytes()[20..32], &[0u8; 12]);
    }

    #[test]
    fn test_set_type_values() {
        let mut adrs = Address::new();
        adrs.set_type(AddressType::ForsTree);
        assert_eq!(&adrs.as_bytes()[16..20], &[0, 0, 0, 3]);
        adrs.set_type(AddressType::ForsPrf);
        assert_eq!(&adrs.as_bytes()[16..20], &[0, 0, 0, 6]);
    }

    #[test]
    fn test_key_pair_address_roundtrip() {
        let mut adrs = Address::new();
        adrs.set_key_pair_address(1234);
        assert_eq!(adrs.get_key_pair_address(), 1234);
    }

    #[test]
    fn test_tree_index_roundtrip() {
        let mut adrs = Address::new();
        adrs.set_tree_index(0xDEADBEEF);
        assert_eq!(adrs.get_tree_index(), 0xDEADBEEF);
    }

    #[test]
    fn test_chain_and_height_share_field() {
        let mut adrs = Address::new();
        adrs.set_chain_address(42);
        assert_eq!(&adrs.as_bytes()[24..28], &[0, 0, 0, 42]);
        adrs.set_tree_height(99);
        // tree_height overwrites the same bytes as chain_address.
        assert_eq!(&adrs.as_bytes()[24..28], &[0, 0, 0, 99]);
    }

    #[test]
    fn test_hash_and_index_share_field() {
        let mut adrs = Address::new();
        adrs.set_hash_address(10);
        assert_eq!(&adrs.as_bytes()[28..32], &[0, 0, 0, 10]);
        adrs.set_tree_index(20);
        // tree_index overwrites the same bytes as hash_address.
        assert_eq!(&adrs.as_bytes()[28..32], &[0, 0, 0, 20]);
    }

    #[test]
    fn test_copy() {
        let mut adrs = Address::new();
        adrs.set_layer_address(3);
        adrs.set_tree_address(42);
        let adrs2 = adrs.copy();
        assert_eq!(adrs.as_bytes(), adrs2.as_bytes());
    }

    #[test]
    fn test_address_type_enum_values() {
        assert_eq!(AddressType::WotsHash as u32, 0);
        assert_eq!(AddressType::WotsPk as u32, 1);
        assert_eq!(AddressType::Tree as u32, 2);
        assert_eq!(AddressType::ForsTree as u32, 3);
        assert_eq!(AddressType::ForsRoots as u32, 4);
        assert_eq!(AddressType::WotsPrf as u32, 5);
        assert_eq!(AddressType::ForsPrf as u32, 6);
    }
}

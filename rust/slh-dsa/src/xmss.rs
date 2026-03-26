//! XMSS tree operations (FIPS 205, Algorithms 8-10).
//!
//! Implements the eXtended Merkle Signature Scheme used within each
//! hypertree layer.

use alloc::vec::Vec;

use crate::address::{Address, AddressType};
use crate::hash::HashSuite;
use crate::wots;

/// Compute an XMSS tree node via recursive treehash (Algorithm 8).
///
/// Returns the node at height `z` and horizontal index `i` in the XMSS
/// tree. At height 0, this is a WOTS+ public key leaf. Higher nodes are
/// computed by hashing their two children with H.
pub fn xmss_node<H: HashSuite>(
    sk_seed: &[u8],
    i: u32,
    z: u32,
    pk_seed: &[u8],
    adrs: &mut Address,
    n: usize,
    len: usize,
) -> Vec<u8> {
    if z == 0 {
        // Leaf node: WOTS+ public key
        adrs.set_type(AddressType::WotsHash);
        adrs.set_key_pair_address(i);
        wots::wots_pkgen::<H>(sk_seed, pk_seed, adrs, n, len)
    } else {
        // Internal node: hash of left and right children
        let left = xmss_node::<H>(sk_seed, 2 * i, z - 1, pk_seed, adrs, n, len);
        let right = xmss_node::<H>(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, n, len);
        adrs.set_type(AddressType::Tree);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        H::h(pk_seed, adrs, &left, &right, n)
    }
}

/// XMSS signature generation (Algorithm 9).
///
/// Signs an n-byte message `m` at leaf index `idx` within the XMSS tree.
/// Returns a WOTS+ signature concatenated with the authentication path
/// (hp sibling nodes).
pub fn xmss_sign<H: HashSuite>(
    m: &[u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    adrs: &mut Address,
    n: usize,
    hp: u32,
    len: usize,
) -> Vec<u8> {
    // Generate WOTS+ signature for the message
    adrs.set_type(AddressType::WotsHash);
    adrs.set_key_pair_address(idx);
    let sig = wots::wots_sign::<H>(
        m, sk_seed, pk_seed, adrs, n, len,
        len - 3, // len1
        3,        // len2
    );

    // Build authentication path
    let mut auth = Vec::with_capacity((hp as usize) * n);
    let mut k = idx;
    for j in 0..hp {
        // Sibling index at height j
        let sibling = k ^ 1;
        let node = xmss_node::<H>(sk_seed, sibling, j, pk_seed, adrs, n, len);
        auth.extend_from_slice(&node);
        k >>= 1;
    }

    // sig_xmss = sig_wots || auth
    let mut sig_xmss = sig;
    sig_xmss.extend_from_slice(&auth);
    sig_xmss
}

/// XMSS public key recovery from signature (Algorithm 10).
///
/// Given an XMSS signature (WOTS+ sig + auth path), the signed message,
/// and the leaf index, recovers the XMSS tree root.
pub fn xmss_pk_from_sig<H: HashSuite>(
    idx: u32,
    sig_xmss: &[u8],
    m: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
    n: usize,
    hp: u32,
    len: usize,
) -> Vec<u8> {
    // Split signature into WOTS+ signature and authentication path
    let wots_sig_len = len * n;
    let sig_wots = &sig_xmss[..wots_sig_len];
    let auth = &sig_xmss[wots_sig_len..];

    // Recover WOTS+ public key
    adrs.set_type(AddressType::WotsHash);
    adrs.set_key_pair_address(idx);
    let mut node = wots::wots_pk_from_sig::<H>(
        sig_wots, m, pk_seed, adrs, n, len,
        len - 3, // len1
        3,        // len2
    );

    // Walk up the tree using the authentication path
    adrs.set_type(AddressType::Tree);
    let mut k = idx;
    for j in 0..hp {
        adrs.set_tree_height(j + 1);
        let auth_j = &auth[(j as usize) * n..(j as usize + 1) * n];
        if k % 2 == 0 {
            // node is left child
            adrs.set_tree_index(k / 2);
            node = H::h(pk_seed, adrs, &node, auth_j, n);
        } else {
            // node is right child
            adrs.set_tree_index(k / 2);
            node = H::h(pk_seed, adrs, auth_j, &node, n);
        }
        k >>= 1;
    }
    node
}

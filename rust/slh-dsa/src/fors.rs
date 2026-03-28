//! FORS — Forest of Random Subsets (FIPS 205, Algorithms 13-16).
//!
//! FORS is a few-time signature scheme used in SLH-DSA to sign the
//! message digest. It consists of `k` binary trees, each with `2^a`
//! leaves.

use alloc::vec::Vec;

use crate::address::{Address, AddressType};
use crate::hash::HashSuite;
use crate::utils::base_2b;

/// Generate a FORS secret key element (Algorithm 13).
///
/// Derives the secret value for leaf `idx` using PRF.
pub fn fors_skgen<H: HashSuite>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    idx: u32,
    n: usize,
) -> Vec<u8> {
    let mut sk_adrs = adrs.copy();
    sk_adrs.set_type(AddressType::ForsPrf);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
    sk_adrs.set_tree_index(idx);
    H::prf(pk_seed, sk_seed, &sk_adrs, n)
}

/// Compute a FORS tree node via recursive treehash (Algorithm 14).
///
/// Returns the node at height `z` and horizontal index `i`.
/// The original `adrs` is never modified; local copies are used for all hash calls.
pub fn fors_node<H: HashSuite>(
    sk_seed: &[u8],
    i: u32,
    z: u32,
    pk_seed: &[u8],
    adrs: &Address,
    n: usize,
) -> Vec<u8> {
    let kp = adrs.get_key_pair_address();
    if z == 0 {
        // Leaf: hash the secret key element
        let sk = fors_skgen::<H>(sk_seed, pk_seed, adrs, i, n);
        let mut node_adrs = adrs.copy();
        node_adrs.set_type(AddressType::ForsTree);
        node_adrs.set_key_pair_address(kp);
        node_adrs.set_tree_height(0);
        node_adrs.set_tree_index(i);
        H::f(pk_seed, &node_adrs, &sk, n)
    } else {
        let left = fors_node::<H>(sk_seed, 2 * i, z - 1, pk_seed, adrs, n);
        let right = fors_node::<H>(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, n);
        let mut node_adrs = adrs.copy();
        node_adrs.set_type(AddressType::ForsTree);
        node_adrs.set_key_pair_address(kp);
        node_adrs.set_tree_height(z);
        node_adrs.set_tree_index(i);
        H::h(pk_seed, &node_adrs, &left, &right, n)
    }
}

/// FORS signature generation (Algorithm 15).
///
/// Signs the message digest `md` (which selects k leaf indices from k
/// FORS trees). Returns SIG_FORS = k * (sk_value + a auth nodes).
pub fn fors_sign<H: HashSuite>(
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    n: usize,
    k: usize,
    a: usize,
) -> Vec<u8> {
    let indices = base_2b(md, a as u32, k);
    let mut sig_fors = Vec::with_capacity(k * (1 + a) * n);

    for i in 0..k {
        let idx = indices[i];
        // Absolute leaf index within the FORS forest for this tree
        let abs_idx = (i as u32) * (1u32 << a) + idx;

        // Secret key value
        let sk = fors_skgen::<H>(sk_seed, pk_seed, adrs, abs_idx, n);
        sig_fors.extend_from_slice(&sk);

        // Authentication path for tree i
        let mut s = idx;
        for j in 0..(a as u32) {
            // Sibling node at height j
            let tree_offset = (i as u32) * (1u32 << (a as u32 - j));
            let node = fors_node::<H>(sk_seed, tree_offset + (s ^ 1), j, pk_seed, adrs, n);
            sig_fors.extend_from_slice(&node);
            s >>= 1;
        }
    }
    sig_fors
}

/// FORS public key recovery from signature (Algorithm 16).
///
/// Given a FORS signature and the message digest, recovers the FORS
/// public key by rebuilding each tree root and compressing them.
pub fn fors_pk_from_sig<H: HashSuite>(
    sig_fors: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    n: usize,
    k: usize,
    a: usize,
) -> Vec<u8> {
    let indices = base_2b(md, a as u32, k);
    let mut roots = Vec::with_capacity(k * n);
    let kp = adrs.get_key_pair_address();

    let chunk_size = (1 + a) * n;

    for i in 0..k {
        let sig_chunk = &sig_fors[i * chunk_size..(i + 1) * chunk_size];
        let sk_val = &sig_chunk[..n];
        let auth = &sig_chunk[n..];

        let idx = indices[i];
        let abs_idx = (i as u32) * (1u32 << a) + idx;

        // Compute leaf from secret value
        let mut node_adrs = adrs.copy();
        node_adrs.set_type(AddressType::ForsTree);
        node_adrs.set_key_pair_address(kp);
        node_adrs.set_tree_height(0);
        node_adrs.set_tree_index(abs_idx);
        let mut node = H::f(pk_seed, &node_adrs, sk_val, n);

        // Walk up using auth path
        let mut s = idx;
        for j in 0..(a as u32) {
            let auth_j = &auth[(j as usize) * n..(j as usize + 1) * n];
            node_adrs.set_tree_height(j + 1);
            node_adrs.set_tree_index(abs_idx >> (j + 1));
            if s % 2 == 0 {
                node = H::h(pk_seed, &node_adrs, &node, auth_j, n);
            } else {
                node = H::h(pk_seed, &node_adrs, auth_j, &node, n);
            }
            s >>= 1;
        }
        roots.extend_from_slice(&node);
    }

    // Compress all k roots with T_k
    let mut fors_pk_adrs = adrs.copy();
    fors_pk_adrs.set_type(AddressType::ForsRoots);
    fors_pk_adrs.set_key_pair_address(kp);
    let blocks: Vec<&[u8]> = (0..k).map(|i| &roots[i * n..(i + 1) * n]).collect();
    H::t_l(pk_seed, &fors_pk_adrs, &blocks, n)
}

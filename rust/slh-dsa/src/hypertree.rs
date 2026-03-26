//! Hypertree operations (FIPS 205, Algorithms 11-12).
//!
//! The hypertree is a certification tree of XMSS trees stacked in `d`
//! layers. The bottom layer signs the FORS public key, and each
//! subsequent layer certifies the root of the layer below.

use alloc::vec::Vec;

use crate::address::Address;
use crate::hash::HashSuite;
use crate::xmss;

/// Hypertree signature generation (Algorithm 11).
///
/// Signs an n-byte message `m` at position (idx_tree, idx_leaf) in the
/// bottom XMSS layer, then certifies upward through all `d` layers.
pub fn ht_sign<H: HashSuite>(
    m: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    n: usize,
    d: usize,
    hp: u32,
    len: usize,
) -> Vec<u8> {
    let mut adrs = Address::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    // Sign at the bottom layer
    let sig_tmp = xmss::xmss_sign::<H>(m, sk_seed, idx_leaf, pk_seed, &mut adrs, n, hp, len);
    let mut sig_ht = sig_tmp;

    // Recover root of the bottom XMSS tree
    let xmss_sig_size = (len + hp as usize) * n;
    let mut root = xmss::xmss_pk_from_sig::<H>(
        idx_leaf,
        &sig_ht[..xmss_sig_size],
        m,
        pk_seed,
        &mut adrs,
        n,
        hp,
        len,
    );

    let mut tree = idx_tree;
    let mut leaf;

    // Sign upward through remaining layers
    for j in 1..d {
        leaf = (tree & ((1u64 << hp) - 1)) as u32;
        tree >>= hp;

        adrs.set_layer_address(j as u32);
        adrs.set_tree_address(tree);

        let sig_tmp =
            xmss::xmss_sign::<H>(&root, sk_seed, leaf, pk_seed, &mut adrs, n, hp, len);
        sig_ht.extend_from_slice(&sig_tmp);

        if j < d - 1 {
            root = xmss::xmss_pk_from_sig::<H>(
                leaf,
                &sig_tmp,
                &root,
                pk_seed,
                &mut adrs,
                n,
                hp,
                len,
            );
        }
    }

    sig_ht
}

/// Hypertree signature verification (Algorithm 12).
///
/// Verifies a hypertree signature by recovering each XMSS root from
/// the bottom layer upward, checking that the final root matches the
/// public key root.
pub fn ht_verify<H: HashSuite>(
    m: &[u8],
    sig_ht: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8],
    n: usize,
    d: usize,
    hp: u32,
    len: usize,
) -> bool {
    let xmss_sig_size = (len + hp as usize) * n;

    let mut adrs = Address::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    let sig_tmp = &sig_ht[..xmss_sig_size];
    let mut node = xmss::xmss_pk_from_sig::<H>(
        idx_leaf, sig_tmp, m, pk_seed, &mut adrs, n, hp, len,
    );

    let mut tree = idx_tree;
    let mut leaf;

    for j in 1..d {
        leaf = (tree & ((1u64 << hp) - 1)) as u32;
        tree >>= hp;

        adrs.set_layer_address(j as u32);
        adrs.set_tree_address(tree);

        let sig_offset = j * xmss_sig_size;
        let sig_tmp = &sig_ht[sig_offset..sig_offset + xmss_sig_size];
        node = xmss::xmss_pk_from_sig::<H>(
            leaf, sig_tmp, &node, pk_seed, &mut adrs, n, hp, len,
        );
    }

    node == pk_root
}

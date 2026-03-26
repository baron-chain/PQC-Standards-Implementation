//! WOTS+ one-time signature scheme (FIPS 205, Algorithms 4-7).
//!
//! Implements the Winternitz One-Time Signature Plus scheme used as the
//! building block for XMSS trees in SLH-DSA.

use alloc::vec::Vec;

use crate::address::{Address, AddressType};
use crate::hash::HashSuite;
use crate::utils::base_2b;

/// WOTS+ chaining function (Algorithm 4).
///
/// Starting from value `x`, applies F iteratively `s` times beginning at
/// index `i`. Returns F^s(x) with appropriate address tweaking.
pub fn chain<H: HashSuite>(
    x: &[u8],
    i: u32,
    s: u32,
    pk_seed: &[u8],
    adrs: &mut Address,
    n: usize,
) -> Vec<u8> {
    if s == 0 {
        return x.to_vec();
    }
    let mut tmp = x.to_vec();
    for j in i..(i + s) {
        adrs.set_hash_address(j);
        tmp = H::f(pk_seed, adrs, &tmp, n);
    }
    tmp
}

/// WOTS+ public key generation (Algorithm 5).
///
/// Generates a WOTS+ public key by chaining each secret key element to
/// the top of its chain and compressing with T_len.
pub fn wots_pkgen<H: HashSuite>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
    n: usize,
    len: usize,
) -> Vec<u8> {
    let mut sk_adrs = adrs.copy();
    sk_adrs.set_type(AddressType::WotsPrf);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    let mut tmp = Vec::with_capacity(len * n);
    for i in 0..len {
        sk_adrs.set_chain_address(i as u32);
        let sk = H::prf(pk_seed, sk_seed, &sk_adrs, n);
        adrs.set_chain_address(i as u32);
        let chain_val = chain::<H>(&sk, 0, 15, pk_seed, adrs, n);
        tmp.extend_from_slice(&chain_val);
    }

    // Compress with T_len
    let mut wots_pk_adrs = adrs.copy();
    wots_pk_adrs.set_type(AddressType::WotsPk);
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    let blocks: Vec<&[u8]> = (0..len).map(|i| &tmp[i * n..(i + 1) * n]).collect();
    H::t_l(pk_seed, &wots_pk_adrs, &blocks, n)
}

/// WOTS+ signature generation (Algorithm 6).
///
/// Signs an n-byte message digest `m` using the WOTS+ secret key derived
/// from `sk_seed`. The message is decomposed into base-16 digits, a
/// checksum is appended, and each chain is evaluated to the appropriate
/// height.
pub fn wots_sign<H: HashSuite>(
    m: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
    n: usize,
    len: usize,
    len1: usize,
    len2: usize,
) -> Vec<u8> {
    // Convert message to base-16 digits
    let msg_digits = base_2b(m, 4, len1);

    // Compute checksum
    let mut csum: u32 = 0;
    for &d in &msg_digits {
        csum += 15 - d;
    }
    // Left-shift checksum: ls = 8 - ((len2 * lg_w) % 8)
    let ls = 8 - ((len2 * 4) % 8);
    if ls != 8 {
        csum <<= ls;
    }

    // Convert checksum to base-16 digits
    let csum_bytes_len = (len2 * 4 + 7) / 8; // ceiling
    let csum_bytes = crate::utils::to_byte(csum as u64, csum_bytes_len);
    let csum_digits = base_2b(&csum_bytes, 4, len2);

    // Concatenate message and checksum digits
    let mut all_digits = msg_digits;
    all_digits.extend_from_slice(&csum_digits);

    // Generate signature
    let mut sk_adrs = adrs.copy();
    sk_adrs.set_type(AddressType::WotsPrf);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    let mut sig = Vec::with_capacity(len * n);
    for i in 0..len {
        sk_adrs.set_chain_address(i as u32);
        let sk = H::prf(pk_seed, sk_seed, &sk_adrs, n);
        adrs.set_chain_address(i as u32);
        let chain_val = chain::<H>(&sk, 0, all_digits[i], pk_seed, adrs, n);
        sig.extend_from_slice(&chain_val);
    }
    sig
}

/// WOTS+ public key recovery from signature (Algorithm 7).
///
/// Given a WOTS+ signature and the original message, recovers the
/// public key by completing each chain from where signing stopped.
pub fn wots_pk_from_sig<H: HashSuite>(
    sig: &[u8],
    m: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
    n: usize,
    len: usize,
    len1: usize,
    len2: usize,
) -> Vec<u8> {
    // Convert message to base-16 digits
    let msg_digits = base_2b(m, 4, len1);

    // Compute checksum
    let mut csum: u32 = 0;
    for &d in &msg_digits {
        csum += 15 - d;
    }
    let ls = 8 - ((len2 * 4) % 8);
    if ls != 8 {
        csum <<= ls;
    }

    let csum_bytes_len = (len2 * 4 + 7) / 8;
    let csum_bytes = crate::utils::to_byte(csum as u64, csum_bytes_len);
    let csum_digits = base_2b(&csum_bytes, 4, len2);

    let mut all_digits = msg_digits;
    all_digits.extend_from_slice(&csum_digits);

    // Recover public key chains
    let mut tmp = Vec::with_capacity(len * n);
    for i in 0..len {
        adrs.set_chain_address(i as u32);
        let sig_i = &sig[i * n..(i + 1) * n];
        let chain_val = chain::<H>(sig_i, all_digits[i], 15 - all_digits[i], pk_seed, adrs, n);
        tmp.extend_from_slice(&chain_val);
    }

    // Compress with T_len
    let mut wots_pk_adrs = adrs.copy();
    wots_pk_adrs.set_type(AddressType::WotsPk);
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    let blocks: Vec<&[u8]> = (0..len).map(|i| &tmp[i * n..(i + 1) * n]).collect();
    H::t_l(pk_seed, &wots_pk_adrs, &blocks, n)
}

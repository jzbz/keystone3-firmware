//! Decred (DCR) support for Keystone: a no_std signing core ported from the
//! KeyOS `decred-core` crate.
//!
//! Scope is deliberately narrow: account xpub → P2PKH addresses → SigHashAll →
//! low-S ECDSA. No staking, no mixing, no transaction *construction* policy
//! (the watch-only companion does that). This crate only turns an unsigned-tx
//! package into a signed, network-serializable tx, plus the address/dpub
//! helpers the firmware UI needs.
//!
//! EC math and BIP32 are delegated to the same `bitcoin` crate the rest of the
//! firmware uses. The only Decred-specific cryptographic primitive vendored
//! here is BLAKE-256 (the 14-round SHA-3 finalist Decred uses for
//! *everything*, not BLAKE2/3), implemented in `blake256.rs` and checked
//! against dcrd KATs. Every algorithm was written against dcrd source and is
//! exercised by reference vectors lifted from dcrd plus a real mainnet
//! transaction in `tests/`.

#![no_std]

extern crate alloc;

pub mod address;
pub mod airgap;
pub mod blake256;
pub mod errors;
pub mod hashing;
pub mod hd;
pub mod sighash;
pub mod sign;
pub mod tx;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin::secp256k1::Secp256k1;

use crate::airgap::{decode_sign_request, sign_request};
use crate::errors::Result;
use crate::hd::{parse_account_xpub, pubkey_from_xpub};

const ATOMS_PER_DCR: i64 = 100_000_000;

/// Format an atom amount for display: `"1.2345 DCR"`, trailing zeros trimmed.
pub fn format_amount(atoms: i64) -> String {
    let sign = if atoms < 0 { "-" } else { "" };
    let abs = atoms.unsigned_abs();
    let whole = abs / ATOMS_PER_DCR as u64;
    let frac = abs % ATOMS_PER_DCR as u64;
    if frac == 0 {
        return format!("{}{} DCR", sign, whole);
    }
    let mut frac_str = format!("{:08}", frac);
    while frac_str.ends_with('0') {
        frac_str.pop();
    }
    format!("{}{}.{} DCR", sign, whole, frac_str)
}

/// One display row of the transaction review screen.
pub struct DisplayItem {
    pub address: String,
    pub value: String,
}

/// Everything the review UI needs, pre-formatted. All classification is done
/// by the device itself from the account xpub — the companion's claims are
/// only used for the `flagged` tamper warnings.
pub struct ParsedDcrTx {
    pub network: String,
    /// Total paid to external recipients (excludes change) — the headline
    /// "Amount" on the review screen.
    pub total_send_value: String,
    pub total_input_value: String,
    pub total_output_value: String,
    pub fee_value: String,
    pub from: Vec<DisplayItem>,
    pub to: Vec<DisplayItem>,
    pub change: Vec<DisplayItem>,
    /// Outputs the companion mislabelled as change but the device cannot
    /// derive as its own. Non-empty means the companion is faulty or hostile.
    pub flagged: Vec<DisplayItem>,
}

/// Decode + trustlessly classify a `dcr-sign-request` payload for review.
pub fn parse_sign_request(payload: &[u8], account_xpub: &str) -> Result<ParsedDcrTx> {
    let secp = Secp256k1::new();
    let req = decode_sign_request(payload)?;
    let summary = req.review_owned(&secp, account_xpub)?;

    // Inputs are all ours (enforced by check_sign_request before signing);
    // show the spending addresses so the user can cross-check.
    let account = parse_account_xpub(account_xpub)?;
    let mut from = Vec::new();
    for input in &req.inputs {
        let address = match pubkey_from_xpub(&secp, &account, input.branch, input.index) {
            Ok(pubkey) => address::p2pkh_from_pubkey(&pubkey),
            Err(_) => "<unknown input>".to_string(),
        };
        from.push(DisplayItem {
            address,
            value: format_amount(input.value_in),
        });
    }

    let items = |v: Vec<(String, i64)>| -> Vec<DisplayItem> {
        v.into_iter()
            .map(|(address, value)| DisplayItem {
                address,
                value: format_amount(value),
            })
            .collect()
    };

    let send_total: i64 = summary.recipients.iter().map(|r| r.1).sum();
    Ok(ParsedDcrTx {
        network: "Decred Mainnet".to_string(),
        total_send_value: format_amount(send_total),
        total_input_value: format_amount(summary.input_total),
        total_output_value: format_amount(summary.output_total),
        fee_value: format_amount(summary.fee),
        from,
        to: items(summary.recipients),
        change: items(summary.change),
        flagged: items(summary.flagged_mismatches),
    })
}

/// Pre-sign validation of a `dcr-sign-request` payload: format version, input
/// ownership (prev_script must re-derive from our xpub), amount sanity.
pub fn check_sign_request(payload: &[u8], account_xpub: &str) -> Result<()> {
    let secp = Secp256k1::new();
    let req = decode_sign_request(payload)?;
    req.check_owned_inputs(&secp, account_xpub)
}

/// Sign a `dcr-sign-request` payload with the wallet seed and return the
/// broadcast-ready full transaction bytes for the `dcr-signed-tx` reply.
pub fn sign_sign_request(payload: &[u8], seed: &[u8]) -> Result<Vec<u8>> {
    let secp = Secp256k1::new();
    let req = decode_sign_request(payload)?;
    sign_request(&secp, seed, &req)
}

/// Receive address at `branch/index` below the stored account xpub.
pub fn get_address(account_xpub: &str, branch: u32, index: u32) -> Result<String> {
    let secp = Secp256k1::new();
    let account = parse_account_xpub(account_xpub)?;
    let pubkey = pubkey_from_xpub(&secp, &account, branch, index)?;
    Ok(address::p2pkh_from_pubkey(&pubkey))
}

/// The `dpub…` export a watch-only Decred companion imports.
pub fn get_dpub(account_xpub: &str) -> Result<String> {
    hd::xpub_to_dpub(account_xpub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_formatting() {
        assert_eq!(format_amount(0), "0 DCR");
        assert_eq!(format_amount(100_000_000), "1 DCR");
        assert_eq!(format_amount(123_456_789), "1.23456789 DCR");
        assert_eq!(format_amount(120_000_000), "1.2 DCR");
        assert_eq!(format_amount(-50_000_000), "-0.5 DCR");
    }
}

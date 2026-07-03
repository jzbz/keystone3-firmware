//! Decred (DCR) support for Keystone: a thin firmware adapter over the shared
//! [`dcr-rs`](https://github.com/jzbz/dcr-rs) library.
//!
//! All consensus-critical logic — BLAKE-256, addresses, BIP32 with Decred
//! serialization, the tx wire format, the sighash, ECDSA signature scripts and
//! the air-gapped CBOR package (shared with the KeyOS signer) — lives in
//! dcr-rs, where it is pinned by dcrd reference vectors and a real mainnet
//! transaction. This crate only:
//!   * bridges the firmware's stored account `xpub…` string (standard BIP32
//!     encoding, see `account_public_info.c`) to a dcr-rs [`ExtPubKey`],
//!   * pre-formats amounts/addresses into the review-screen structs, and
//!   * maps errors onto the firmware error codes (see `errors.rs`).
//!
//! Trust model is unchanged: all display classification is done by the device
//! itself from the account xpub, and signing re-derives every input key — the
//! companion's claims are only used for the `flagged` tamper warnings.

#![no_std]

extern crate alloc;

pub mod errors;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use bitcoin::bip32::Xpub;
use dcr_rs::hd::{ExtPrivKey, ExtPubKey};
use dcr_rs::secp256k1::Secp256k1;
use dcr_rs::{airgap, Address, Network};

use crate::errors::{DecredError, Result};

pub use dcr_rs::format_amount;

/// Branch constants shared with the companion protocol.
pub mod hd {
    pub use dcr_rs::hd::{BRANCH_EXTERNAL, BRANCH_INTERNAL};
}

/// Parse the stored account-level `xpub…` string into a mainnet dcr-rs key.
/// The firmware stores the standard BIP32 form (double-SHA256 checksum); only
/// the version bytes and checksum differ from Decred's `dpub` encoding — the
/// 74-byte key body is identical, so the fields carry over one-to-one.
fn account_from_xpub(xpub: &str) -> Result<ExtPubKey> {
    let key = Xpub::from_str(xpub.trim())
        .map_err(|e| DecredError::GenerateAddressError(e.to_string()))?;
    Ok(ExtPubKey {
        network: Network::Mainnet,
        public_key: key.public_key,
        chain_code: key.chain_code.to_bytes(),
        depth: key.depth,
        parent_fingerprint: key.parent_fingerprint.to_bytes(),
        child_number: u32::from(key.child_number),
    })
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

/// If the companion stamped the request with the fingerprint of the account
/// it was built against, refuse with a friendly message when it isn't ours —
/// long before the prev_script check would fail with a bare mismatch. Never a
/// security control (the script re-derivation remains the fund protector).
fn check_account_fp(req: &airgap::SignRequest, account: &ExtPubKey) -> Result<()> {
    if let Some(fp) = req.account_fp {
        if account.fingerprint() != fp {
            return Err(DecredError::InvalidDataError(
                "this transaction was built for a different wallet or account".to_string(),
            ));
        }
    }
    Ok(())
}

/// Decode + trustlessly classify a `dcr-sign-request` payload for review.
pub fn parse_sign_request(payload: &[u8], account_xpub: &str) -> Result<ParsedDcrTx> {
    let secp = Secp256k1::new();
    let req = airgap::decode_sign_request(payload)?;
    // Structural/economic sanity before anything is formatted for display:
    // the review screen must never render dishonest math (duplicate inputs,
    // out-of-range or overflowing amounts, negative fees), regardless of
    // whether the check step already ran.
    req.validate()?;
    let account = account_from_xpub(account_xpub)?;
    check_account_fp(&req, &account)?;
    let summary = req.review_owned(&secp, &account)?;

    // Inputs are all ours (enforced by check_sign_request before signing);
    // show the spending addresses so the user can cross-check.
    let mut from = Vec::new();
    for input in &req.inputs {
        let address = match account.pubkey_at(&secp, input.branch, input.index) {
            Ok(pubkey) => Address::from_pubkey(&pubkey, Network::Mainnet).encode(),
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
    let req = airgap::decode_sign_request(payload)?;
    let account = account_from_xpub(account_xpub)?;
    check_account_fp(&req, &account)?;
    // Runs validate() first (structural/economic sanity), then re-derives
    // every input's script from our xpub.
    Ok(req.check_owned_inputs(&secp, &account)?)
}

/// Sign a `dcr-sign-request` payload with the wallet seed and return the
/// broadcast-ready full transaction bytes for the `dcr-signed-tx` reply.
pub fn sign_sign_request(payload: &[u8], seed: &[u8]) -> Result<Vec<u8>> {
    let secp = Secp256k1::new();
    let req = airgap::decode_sign_request(payload)?;
    let master = ExtPrivKey::master_from_seed(seed, Network::Mainnet)
        .map_err(|_| DecredError::SigningError("invalid seed".to_string()))?;
    Ok(airgap::sign_request(&secp, &master, &req)?)
}

/// Receive address at `branch/index` below the stored account xpub.
pub fn get_address(account_xpub: &str, branch: u32, index: u32) -> Result<String> {
    let secp = Secp256k1::new();
    let account = account_from_xpub(account_xpub)?;
    let pubkey = account.pubkey_at(&secp, branch, index)?;
    Ok(Address::from_pubkey(&pubkey, Network::Mainnet).encode())
}

/// The `dpub…` export a watch-only Decred companion imports.
pub fn get_dpub(account_xpub: &str) -> Result<String> {
    Ok(account_from_xpub(account_xpub)?.to_base58())
}

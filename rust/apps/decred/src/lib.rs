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
//! Trust model, as of dcr-rs format version 3: display classification is done by
//! the device from the account xpub, signing re-derives every input key, and input
//! amounts are verified against the funding transaction each input carries rather
//! than taken on the companion's word. `validate()` performs that verification, so
//! both the display and the signing paths are covered by it.

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

/// The BIP44 account level: `m / 44' / 42' / account'`.
const ACCOUNT_DEPTH: u8 = 3;

/// Parse the stored account-level `xpub…` string into a mainnet dcr-rs key.
/// The firmware stores the standard BIP32 form (double-SHA256 checksum); only
/// the version bytes and checksum differ from Decred's `dpub` encoding — the
/// 74-byte key body is identical, so the fields carry over one-to-one.
fn account_from_xpub(xpub: &str) -> Result<ExtPubKey> {
    let key = Xpub::from_str(xpub.trim())
        .map_err(|e| DecredError::GenerateAddressError(e.to_string()))?;
    // Xpub::from_str accepts testnet version bytes as readily as mainnet, and the
    // network was previously discarded and hardcoded to Mainnet below. A tpub would
    // therefore have been accepted and used to render Decred MAINNET addresses on
    // the receive screen and the review screen. This build is mainnet-only, so
    // refuse anything else rather than silently reinterpreting it.
    if key.network != bitcoin::NetworkKind::Main {
        return Err(DecredError::GenerateAddressError(
            "expected a mainnet account extended public key".to_string(),
        ));
    }
    // NOTE: depth is deliberately NOT constrained here. This helper also backs the
    // xpub -> dpub conversion and address derivation, which are level-agnostic and
    // are cross-checked against dcrd's published extendedkey_test.go vector for a
    // MASTER key. The account-level requirement is enforced in check_account_key,
    // on the paths that actually treat the key as an account key.
    Ok(ExtPubKey {
        network: Network::Mainnet,
        public_key: key.public_key,
        chain_code: key.chain_code.to_bytes(),
        depth: key.depth,
        parent_fingerprint: key.parent_fingerprint.to_bytes(),
        child_number: u32::from(key.child_number),
    })
}

/// Check that the stored key really is an account key and that the request was
/// built for that same account, before the user is asked for a password.
///
/// Two separate problems, both only reachable on the sign/review paths:
///
/// * `SignRequest::account` selects the account `sign_request` derives from the
///   seed. Without this check a request naming another account passed every
///   pre-approval gate and the whole review screen, then failed inside the signer
///   with a bare `ScriptMismatch` — after the password had been entered and the
///   spend approved.
/// * Everything here derives `branch/index` below the key on the assumption that it
///   sits at the account level. A key from another level would derive a different
///   tree while still producing plausible-looking `Ds…` addresses.
///
/// The expected index comes from the key itself rather than a hardcoded 0: a BIP32
/// account xpub carries its own child number, so this stays correct if the device
/// ever exposes more than one account.
fn check_account_key(req: &airgap::SignRequest, account: &ExtPubKey) -> Result<()> {
    if account.depth != ACCOUNT_DEPTH {
        return Err(DecredError::GenerateAddressError(
            "expected an account-level extended public key".to_string(),
        ));
    }
    let ours = account.child_number & !dcr_rs::hd::HARDENED;
    if req.account != ours {
        return Err(DecredError::WrongWalletOrAccount);
    }
    Ok(())
}

/// One display row of the transaction review screen.
pub struct DisplayItem {
    pub address: String,
    pub value: String,
}

/// Everything the review UI needs, pre-formatted. Every figure here is verified
/// by the device itself: amounts against the funding transaction each input
/// carries, and change against a derivation the device performs. The companion's
/// claims are inputs to those checks, never the basis of what is displayed.
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
    /// Transaction lock time, as a decimal string, or `None` when zero.
    ///
    /// `Some` only when non-zero so the review screen can omit the row entirely in
    /// the overwhelmingly common case, rather than showing every user a "0" they
    /// have to learn to ignore.
    pub lock_time: Option<String>,
    /// Transaction expiry height, as a decimal string, or `None` when zero.
    ///
    /// Decred-specific and worth surfacing: past this height the transaction
    /// becomes permanently invalid. A companion that sets `expiry` to the next
    /// block produces a review screen that looks entirely normal and a transaction
    /// that silently never confirms — repeatable indefinitely as a way to waste a
    /// user's time. It cannot steal anything, but the device should not hide it.
    pub expiry: Option<String>,
}
// NOTE: the `flagged` list is gone along with dcr-rs's `flagged_mismatches`. It
// held outputs the companion called change that the old address scan could not
// derive — a condition format version 2 makes impossible. An output counts as
// change only if a supplied derivation path produces its script, and a path that
// fails to derive is refused before anything reaches the screen. There is no
// longer a soft warning state to render.

/// If the companion stamped the request with the fingerprint of the account
/// it was built against, refuse with a friendly message when it isn't ours —
/// long before the prev_script check would fail with a bare mismatch. Never a
/// security control (the script re-derivation remains the fund protector).
fn check_account_fp(req: &airgap::SignRequest, account: &ExtPubKey) -> Result<()> {
    if let Some(fp) = req.account_fp {
        if account.fingerprint() != fp {
            return Err(DecredError::WrongWalletOrAccount);
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
    check_account_key(&req, &account)?;
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
        lock_time: non_zero(req.lock_time),
        expiry: non_zero(req.expiry),
    })
}

/// Render a height/time field for display, or `None` when it is zero and carries
/// no meaning.
fn non_zero(v: u32) -> Option<String> {
    if v == 0 {
        None
    } else {
        Some(alloc::format!("{v}"))
    }
}

/// Pre-sign validation of a `dcr-sign-request` payload: format version, input
/// ownership (prev_script must re-derive from our xpub), amount sanity.
pub fn check_sign_request(payload: &[u8], account_xpub: &str) -> Result<()> {
    let secp = Secp256k1::new();
    let req = airgap::decode_sign_request(payload)?;
    let account = account_from_xpub(account_xpub)?;
    check_account_fp(&req, &account)?;
    check_account_key(&req, &account)?;
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

/// Extract the BIP44 account index from a Decred account path.
///
/// Accepts exactly `M/44'/42'/<account>'` (case-insensitive leading `m`, `'` or `h`
/// for hardened). Anything else is refused rather than coerced, so a mistyped table
/// entry in `account_public_info.c` fails loudly instead of silently deriving some
/// other wallet.
pub fn account_index_from_path(path: &str) -> Result<u32> {
    let bad = || DecredError::GenerateAddressError(alloc::format!("bad decred account path: {path}"));
    let mut parts = path.trim().split('/');
    match parts.next() {
        Some(p) if p.eq_ignore_ascii_case("m") => {}
        _ => return Err(bad()),
    }
    let mut hardened = |expected: Option<u32>| -> Result<u32> {
        let seg = parts.next().ok_or_else(bad)?;
        let digits = seg
            .strip_suffix('\'')
            .or_else(|| seg.strip_suffix('h'))
            .or_else(|| seg.strip_suffix('H'))
            .ok_or_else(bad)?;
        let v: u32 = digits.parse().map_err(|_| bad())?;
        if v >= crate::hd_hardened() {
            return Err(bad());
        }
        match expected {
            Some(want) if v != want => Err(bad()),
            _ => Ok(v),
        }
    };
    hardened(Some(44))?;
    hardened(Some(42))?;
    let account = hardened(None)?;
    if parts.next().is_some() {
        return Err(bad());
    }
    Ok(account)
}

/// The hardened-index threshold, kept as a helper so the parser above does not need
/// to name dcr-rs's constant inline.
fn hd_hardened() -> u32 {
    dcr_rs::hd::HARDENED
}

/// Derive the Decred account extended public key from the seed, returned in the
/// standard BIP32 `xpub…` encoding the firmware stores.
///
/// This exists because Decred's hardened derivation is NOT strict BIP32. dcrd's
/// hdkeychain strips leading zero bytes from a child private key before feeding it
/// to the next hardened HMAC, and dcrwallet uses that variant for the whole
/// `m/44'/42'/account'` path. The firmware's shared secp256k1 keystore helper
/// implements strict BIP32, so for roughly one seed in 130 -- those where an
/// intermediate hardened child key has a leading zero byte -- it produces a
/// different account key from every other Decred wallet holding the same phrase.
///
/// Deriving here instead means the stored xpub, the exported dpub, the addresses
/// shown on the receive screen and the keys `sign_request` derives from the seed
/// all come from one implementation. Routing Decred through the generic
/// `get_extended_pubkey_by_seed` would leave the display and the signer disagreeing
/// for those seeds: the review would pass, using the stored xpub, and signing would
/// then fail with a script mismatch after the user had already approved.
///
/// Only the encoding is BIP32-standard; the key material is Decred-derived. The
/// firmware stores xpub rather than dpub because everything downstream parses it
/// with [`account_from_xpub`], and the 74-byte key body is identical either way.
pub fn get_account_xpub_by_seed(seed: &[u8], account: u32) -> Result<String> {
    let secp = Secp256k1::new();
    let master = ExtPrivKey::master_from_seed(seed, Network::Mainnet)?;
    let key = master.account_key(&secp, account)?.neuter(&secp);
    let xpub = Xpub {
        network: bitcoin::NetworkKind::Main,
        depth: key.depth,
        parent_fingerprint: bitcoin::bip32::Fingerprint::from(key.parent_fingerprint),
        child_number: bitcoin::bip32::ChildNumber::from(key.child_number),
        public_key: key.public_key,
        chain_code: bitcoin::bip32::ChainCode::from(key.chain_code),
    };
    Ok(xpub.to_string())
}

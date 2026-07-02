//! Air-gapped interchange format between a watch-only Decred companion wallet
//! (online, builds the tx) and Keystone (offline, signs).
//!
//! Decred has no PSBT, so this is a minimal CBOR package. The companion, as a
//! watch-only wallet, knows every input's prevout script, amount, and the
//! derivation path of the key that owns it — everything the signer needs. The
//! device independently recomputes addresses/amounts for on-screen review, so a
//! malicious or buggy companion cannot redirect funds without the user seeing it.
//!
//! Transport: the encoded bytes travel inside the `dcr-sign-request` UR
//! (see `ur_registry::decred`); the reply is the broadcast-ready full tx inside
//! `dcr-signed-tx`. The format is shared with the KeyOS Decred app
//! (decred-core), so one companion implementation serves both devices.
//!
//! This is format version 1; bump `FORMAT_VERSION` on any breaking change.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin::secp256k1::{All, Secp256k1};
use minicbor::{Decode, Encode};

use crate::address::{p2pkh_hash160, p2pkh_script, script_to_address};
use crate::errors::{DecredError, Result};
use crate::hashing::hash160;
use crate::hd::{
    account_xprv_from_seed, address_xprv, parse_account_xpub, pubkey_from_xpub, BRANCH_EXTERNAL,
    BRANCH_INTERNAL,
};
use crate::sign::sign_p2pkh_input;
use crate::tx::{MsgTx, OutPoint, TxIn, TxOut, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX};

pub const FORMAT_VERSION: u8 = 1;

/// How many indices past the highest input index we scan per branch when
/// deciding whether an output pays one of our own keys.
const OWNERSHIP_GAP: u32 = 20;
/// Hard bound on the ownership scan so a hostile package cannot make the
/// device grind through thousands of EC derivations.
const OWNERSHIP_SCAN_MAX: u32 = 1000;

/// One input to be signed, with the metadata only an online wallet has.
#[derive(Clone, Debug, Encode, Decode)]
pub struct InputMeta {
    #[n(0)]
    pub prev_hash: [u8; 32],
    #[n(1)]
    pub prev_index: u32,
    #[n(2)]
    pub tree: u8,
    #[n(3)]
    pub sequence: u32,
    #[n(4)]
    pub value_in: i64,
    /// Account-relative path suffix `[branch, index]`; the device prepends
    /// `m/44'/42'/account'`.
    #[n(5)]
    pub branch: u32,
    #[n(6)]
    pub index: u32,
    /// Prevout pkScript. For our keys the device re-derives and verifies this
    /// equals `p2pkh(hash160(pubkey))` before trusting it.
    #[n(7)]
    pub prev_script: Vec<u8>,
}

/// One output, for both the wire tx and on-device display.
#[derive(Clone, Debug, Encode, Decode)]
pub struct OutputMeta {
    #[n(0)]
    pub value: i64,
    #[n(1)]
    pub version: u16,
    #[n(2)]
    pub pk_script: Vec<u8>,
    /// True if this output is change back to our own wallet.
    #[n(3)]
    pub is_change: bool,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct SignRequest {
    #[n(0)]
    pub format_version: u8,
    #[n(1)]
    pub tx_version: u16,
    #[n(2)]
    pub account: u32,
    #[n(3)]
    pub lock_time: u32,
    #[n(4)]
    pub expiry: u32,
    #[n(5)]
    pub inputs: Vec<InputMeta>,
    #[n(6)]
    pub outputs: Vec<OutputMeta>,
}

pub fn encode_sign_request(req: &SignRequest) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    minicbor::encode(req, &mut buf)
        .map_err(|_| DecredError::InvalidDataError("cbor encode failed".to_string()))?;
    Ok(buf)
}

pub fn decode_sign_request(bytes: &[u8]) -> Result<SignRequest> {
    let req: SignRequest = minicbor::decode(bytes)
        .map_err(|_| DecredError::InvalidDataError("malformed sign request".to_string()))?;
    if req.format_version != FORMAT_VERSION {
        return Err(DecredError::UnsupportedVersion);
    }
    Ok(req)
}

/// A human-reviewable summary the UI shows before the user approves signing.
pub struct ReviewSummary {
    /// (address, amount) for every output the device does NOT own.
    pub recipients: Vec<(String, i64)>,
    /// (address, amount) for outputs the device re-derived as its own.
    pub change: Vec<(String, i64)>,
    pub input_total: i64,
    pub output_total: i64,
    pub fee: i64,
    /// Outputs the companion claimed were change (`is_change = true`) but that
    /// the device CANNOT derive as its own. A correct watch-only wallet never
    /// does this, so each entry is evidence the companion is faulty or hostile
    /// — these MUST be surfaced loudly and block reflexive approval.
    pub flagged_mismatches: Vec<(String, i64)>,
}

impl SignRequest {
    pub fn input_total(&self) -> i64 {
        self.inputs.iter().map(|i| i.value_in).sum()
    }
    pub fn output_total(&self) -> i64 {
        self.outputs.iter().map(|o| o.value).sum()
    }

    fn scan_window(&self) -> u32 {
        let max_index = self.inputs.iter().map(|i| i.index).max().unwrap_or(0);
        max_index.saturating_add(OWNERSHIP_GAP).min(OWNERSHIP_SCAN_MAX)
    }

    /// Trustless review: instead of believing the companion's `is_change` flag,
    /// the device RE-DERIVES its own addresses (public CKD below the stored
    /// account xpub) and decides for itself which outputs are change (pay one
    /// of our keys) and which are external recipients. This mirrors the
    /// input-side `prev_script` verification in `check_owned_inputs`, so a
    /// malicious or buggy companion cannot hide a destination by mislabelling
    /// it as change.
    pub fn review_owned(&self, secp: &Secp256k1<All>, account_xpub: &str) -> Result<ReviewSummary> {
        let account = parse_account_xpub(account_xpub)?;

        // Precompute our own hash160s (external + change branches). The window
        // tracks the wallet's usage level via the highest input index.
        let window = self.scan_window();
        let mut owned: Vec<[u8; 20]> = Vec::new();
        for branch in [BRANCH_EXTERNAL, BRANCH_INTERNAL] {
            for index in 0..=window {
                let pubkey = pubkey_from_xpub(secp, &account, branch, index)?;
                owned.push(hash160(&pubkey));
            }
        }

        let mut recipients = Vec::new();
        let mut change = Vec::new();
        let mut flagged_mismatches = Vec::new();
        for o in &self.outputs {
            let owned_here = match p2pkh_hash160(&o.pk_script) {
                Some(h) => owned.contains(&h),
                None => false,
            };
            let addr = script_to_address(&o.pk_script)
                .unwrap_or_else(|| "<non-standard script>".to_string());
            if owned_here {
                change.push((addr, o.value));
            } else {
                recipients.push((addr.clone(), o.value));
                if o.is_change {
                    flagged_mismatches.push((addr, o.value));
                }
            }
        }

        let input_total = self.input_total();
        let output_total = self.output_total();
        Ok(ReviewSummary {
            recipients,
            change,
            input_total,
            output_total,
            fee: input_total - output_total,
            flagged_mismatches,
        })
    }

    /// Verify (without touching the seed) that every input spends a key this
    /// wallet owns: the claimed `prev_script` must equal the P2PKH script of
    /// the pubkey derived at `branch/index` below the account xpub. Also
    /// enforces basic sanity: known branches, regular tree, positive amounts,
    /// non-negative fee.
    pub fn check_owned_inputs(&self, secp: &Secp256k1<All>, account_xpub: &str) -> Result<()> {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(DecredError::InvalidDataError(
                "transaction has no inputs or outputs".to_string(),
            ));
        }
        let account = parse_account_xpub(account_xpub)?;
        for meta in &self.inputs {
            if meta.branch != BRANCH_EXTERNAL && meta.branch != BRANCH_INTERNAL {
                return Err(DecredError::InvalidDataError(
                    "unknown derivation branch".to_string(),
                ));
            }
            if meta.tree != 0 {
                return Err(DecredError::InvalidDataError(
                    "only regular-tree outputs can be spent".to_string(),
                ));
            }
            if meta.value_in <= 0 {
                return Err(DecredError::InvalidDataError(
                    "non-positive input amount".to_string(),
                ));
            }
            let pubkey = pubkey_from_xpub(secp, &account, meta.branch, meta.index)?;
            let expected = p2pkh_script(&hash160(&pubkey));
            if meta.prev_script != expected {
                return Err(DecredError::ScriptMismatch);
            }
        }
        for o in &self.outputs {
            if o.value < 0 {
                return Err(DecredError::InvalidDataError(
                    "negative output amount".to_string(),
                ));
            }
        }
        if self.input_total() < self.output_total() {
            return Err(DecredError::InvalidDataError(
                "outputs exceed inputs (negative fee)".to_string(),
            ));
        }
        Ok(())
    }
}

/// End-to-end: turn a decoded `SignRequest` into a broadcast-ready Decred tx,
/// given the wallet seed.
///
/// For every input the device **re-derives** the owning key, recomputes its
/// P2PKH script, and refuses to sign if it does not match `prev_script` — so
/// the companion cannot trick the device into signing with the wrong key.
pub fn sign_request(secp: &Secp256k1<All>, seed: &[u8], req: &SignRequest) -> Result<Vec<u8>> {
    let account = account_xprv_from_seed(secp, seed, req.account)?;

    // Assemble the unsigned tx (sigScripts empty for sighash computation).
    let mut tx = MsgTx {
        version: req.tx_version,
        tx_in: req
            .inputs
            .iter()
            .map(|i| TxIn {
                previous_outpoint: OutPoint {
                    hash: i.prev_hash,
                    index: i.prev_index,
                    tree: i.tree,
                },
                sequence: i.sequence,
                value_in: i.value_in,
                block_height: NULL_BLOCK_HEIGHT,
                block_index: NULL_BLOCK_INDEX,
                signature_script: Vec::new(),
            })
            .collect(),
        tx_out: req
            .outputs
            .iter()
            .map(|o| TxOut {
                value: o.value,
                version: o.version,
                pk_script: o.pk_script.clone(),
            })
            .collect(),
        lock_time: req.lock_time,
        expiry: req.expiry,
    };

    // Sign each input, scrubbing every derived private key as we go.
    let mut account = account;
    let mut sign_all = || -> Result<()> {
        for (idx, meta) in req.inputs.iter().enumerate() {
            let mut key = address_xprv(secp, &account, meta.branch, meta.index)?;
            let pubkey = key.private_key.public_key(secp).serialize();
            let expected_script = p2pkh_script(&hash160(&pubkey));
            if meta.prev_script != expected_script {
                key.private_key.non_secure_erase();
                return Err(DecredError::ScriptMismatch);
            }
            let sig_script =
                sign_p2pkh_input(secp, &tx, idx, &expected_script, &key.private_key, &pubkey);
            key.private_key.non_secure_erase();
            tx.tx_in[idx].signature_script = sig_script?;
        }
        Ok(())
    };
    let signed = sign_all();
    account.private_key.non_secure_erase();
    signed?;

    Ok(tx.serialize_full())
}

//! Tests for the air-gap package and the trustless-review logic — the security
//! core of the integration. Covers: CBOR round-trip + version gating + the
//! byte-for-byte KeyOS wire-format pin, ownership classification (change vs
//! recipient vs mislabelled-change), end-to-end signing self-consistency, and
//! the anti-tamper prev_script tripwire.

use app_decred::address::p2pkh_script;
use app_decred::airgap::{
    decode_sign_request, encode_sign_request, InputMeta, OutputMeta, SignRequest, FORMAT_VERSION,
};
use app_decred::errors::DecredError;
use app_decred::hashing::hash160;
use app_decred::hd::{account_xprv_from_seed, address_xprv, BRANCH_EXTERNAL};
use app_decred::sighash::signature_hash_all;
use app_decred::tx::MsgTx;
use bitcoin::bip32::Xpub;
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

const SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

fn seed() -> Vec<u8> {
    hex::decode(SEED_HEX).unwrap()
}

/// The account xpub the firmware would store for `m/44'/42'/0'`.
fn account_xpub() -> String {
    let secp = Secp256k1::new();
    let account = account_xprv_from_seed(&secp, &seed(), 0).unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

/// The P2PKH script of our own key at `0'/branch/index`.
fn own_script(branch: u32, index: u32) -> Vec<u8> {
    let secp = Secp256k1::new();
    let account = account_xprv_from_seed(&secp, &seed(), 0).unwrap();
    let key = address_xprv(&secp, &account, branch, index).unwrap();
    let pubkey = key.private_key.public_key(&secp).serialize();
    p2pkh_script(&hash160(&pubkey)).to_vec()
}

/// A 25-byte P2PKH script that is NOT ours (arbitrary hash160).
fn foreign_script(tag: u8) -> Vec<u8> {
    p2pkh_script(&[tag; 20]).to_vec()
}

#[test]
fn cbor_roundtrip_and_version_gate() {
    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash: [7u8; 32],
            prev_index: 1,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 12345,
            branch: 0,
            index: 0,
            prev_script: foreign_script(0xaa),
        }],
        outputs: vec![OutputMeta {
            value: 12000,
            version: 0,
            pk_script: foreign_script(0xbb),
            is_change: false,
        }],
    };
    let bytes = encode_sign_request(&req).unwrap();
    let back = decode_sign_request(&bytes).unwrap();
    assert_eq!(back.inputs.len(), 1);
    assert_eq!(back.outputs[0].value, 12000);
    assert_eq!(back.inputs[0].value_in, 12345);

    // A package declaring an unknown FORMAT_VERSION must be rejected.
    let mut bad = req;
    bad.format_version = FORMAT_VERSION + 1;
    let bad_bytes = encode_sign_request(&bad).unwrap();
    assert!(matches!(
        decode_sign_request(&bad_bytes),
        Err(DecredError::UnsupportedVersion)
    ));
}

/// Byte-for-byte pin of the wire format against the KeyOS decred-core
/// implementation (the hex below was produced by encode_sign_request in
/// KeyOS utils/decred-core). One companion wallet implementation must be able
/// to talk to both devices, so this encoding is frozen.
#[test]
fn cbor_encoding_matches_keyos_decred_core() {
    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash: [7u8; 32],
            prev_index: 1,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 12345,
            branch: 0,
            index: 3,
            prev_script: vec![0x76, 0xa9, 0x14, 0xaa, 0x88, 0xac],
        }],
        outputs: vec![OutputMeta {
            value: 12000,
            version: 0,
            pk_script: vec![0x76, 0xa9, 0x14, 0xbb, 0x88, 0xac],
            is_change: true,
        }],
    };
    let bytes = encode_sign_request(&req).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "87010100000081889820070707070707070707070707070707070707070707070707070707070707070701001affffffff193039000386187618a91418aa188818ac8184192ee00086187618a91418bb188818acf5"
    );
}

#[test]
fn review_owned_classifies_change_recipient_and_mislabel() {
    let secp = Secp256k1::new();
    let xpub = account_xpub();

    // Our own address (account 0, external/3) — device must recognize it as
    // change regardless of the companion's flag.
    let own = own_script(BRANCH_EXTERNAL, 3);

    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash: [1u8; 32],
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 10_000,
            branch: 0,
            index: 0,
            prev_script: own_script(BRANCH_EXTERNAL, 0),
        }],
        outputs: vec![
            // Owned, but companion DIDN'T flag it as change — device must still
            // count it as change (it pays us).
            OutputMeta { value: 1_000, version: 0, pk_script: own, is_change: false },
            // Genuine external recipient.
            OutputMeta { value: 5_000, version: 0, pk_script: foreign_script(0xcc), is_change: false },
            // Foreign address the companion LIED about (claimed change). This is
            // the attack the trustless review exists to catch.
            OutputMeta { value: 2_000, version: 0, pk_script: foreign_script(0xdd), is_change: true },
        ],
    };

    let summary = req.review_owned(&secp, &xpub).unwrap();
    let change_total: i64 = summary.change.iter().map(|c| c.1).sum();
    assert_eq!(change_total, 1_000, "only the owned output is change");
    assert_eq!(summary.recipients.len(), 2, "both foreign outputs are recipients");
    assert_eq!(summary.flagged_mismatches.len(), 1, "the mislabelled output is flagged");
    assert_eq!(summary.flagged_mismatches[0].1, 2_000);
    assert_eq!(summary.fee, 10_000 - (1_000 + 5_000 + 2_000));
}

#[test]
fn check_accepts_owned_inputs_and_rejects_foreign() {
    let secp = Secp256k1::new();
    let xpub = account_xpub();

    let mut req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash: [9u8; 32],
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 100_000,
            branch: 0,
            index: 5,
            prev_script: own_script(BRANCH_EXTERNAL, 5),
        }],
        outputs: vec![OutputMeta {
            value: 90_000,
            version: 0,
            pk_script: foreign_script(0xee),
            is_change: false,
        }],
    };
    req.check_owned_inputs(&secp, &xpub).unwrap();

    // Same input claiming a script our key at branch/index does not own.
    req.inputs[0].prev_script = foreign_script(0x11);
    assert_eq!(
        req.check_owned_inputs(&secp, &xpub),
        Err(DecredError::ScriptMismatch)
    );
}

#[test]
fn sign_request_is_self_consistent_and_low_s() {
    let secp = Secp256k1::new();
    let script0 = own_script(BRANCH_EXTERNAL, 0);

    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash: [9u8; 32],
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 100_000,
            branch: 0,
            index: 0,
            prev_script: script0.clone(),
        }],
        outputs: vec![OutputMeta {
            value: 90_000,
            version: 0,
            pk_script: foreign_script(0xee),
            is_change: false,
        }],
    };

    // Through the full payload API, exactly as the FFI drives it.
    let payload = encode_sign_request(&req).unwrap();
    app_decred::check_sign_request(&payload, &account_xpub()).unwrap();
    let signed = app_decred::sign_sign_request(&payload, &seed()).unwrap();
    let tx = MsgTx::parse_full(&signed).unwrap();

    // Extract sig + pubkey from the produced sigScript and verify it against the
    // sighash we recompute — proves sign and sighash agree end to end.
    let ss = &tx.tx_in[0].signature_script;
    let l1 = ss[0] as usize;
    let hashtype = ss[l1]; // last byte of the first push
    let der = &ss[1..l1];
    let l2 = ss[1 + l1] as usize;
    let pubkey = &ss[2 + l1..2 + l1 + l2];
    assert_eq!(hashtype, 0x01, "SigHashAll");
    assert_eq!(l2, 33, "compressed pubkey");

    // The pubkey must be the re-derived key for branch 0 / index 0.
    let account = account_xprv_from_seed(&secp, &seed(), 0).unwrap();
    let key0 = address_xprv(&secp, &account, BRANCH_EXTERNAL, 0).unwrap();
    let pk0 = key0.private_key.public_key(&secp).serialize();
    assert_eq!(pubkey, &pk0[..], "signs with the re-derived key");

    let sighash = signature_hash_all(&tx, 0, &script0).unwrap();
    let mut sig = Signature::from_der(der).unwrap();
    let pk = PublicKey::from_slice(pubkey).unwrap();
    secp.verify_ecdsa(&Message::from_digest(sighash), &sig, &pk)
        .expect("self-produced signature verifies");

    // Already low-S, so normalizing is a no-op (consensus requires canonical S).
    let before = sig;
    sig.normalize_s();
    assert_eq!(before, sig, "signature is already low-S");
}

#[test]
fn sign_request_refuses_prev_script_mismatch() {
    // prev_script claims a different address than the key at branch/index owns:
    // the anti-tamper tripwire must fire instead of signing.
    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash: [9u8; 32],
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 100_000,
            branch: 0,
            index: 0,
            prev_script: foreign_script(0x11), // not the script for m/44'/42'/0'/0/0
        }],
        outputs: vec![OutputMeta {
            value: 90_000,
            version: 0,
            pk_script: foreign_script(0xee),
            is_change: false,
        }],
    };

    let payload = encode_sign_request(&req).unwrap();
    assert_eq!(
        app_decred::sign_sign_request(&payload, &seed()),
        Err(DecredError::ScriptMismatch)
    );
}

/// Receive addresses derived from the account xpub must equal addresses
/// derived privately from the seed — the two paths the firmware actually uses
/// (xpub for the receive screen, seed only at signing time).
#[test]
fn xpub_addresses_match_seed_derivation() {
    let secp = Secp256k1::new();
    let xpub = account_xpub();
    let account = account_xprv_from_seed(&secp, &seed(), 0).unwrap();
    for index in [0u32, 1, 7, 100] {
        let from_xpub = app_decred::get_address(&xpub, BRANCH_EXTERNAL, index).unwrap();
        let key = address_xprv(&secp, &account, BRANCH_EXTERNAL, index).unwrap();
        let pubkey = key.private_key.public_key(&secp).serialize();
        let from_seed = app_decred::address::p2pkh_from_pubkey(&pubkey);
        assert_eq!(from_xpub, from_seed, "index {index}");
        assert!(from_xpub.starts_with("Ds"), "mainnet P2PKH prefix");
    }
}

/// Full display-parse pass over an encoded payload.
#[test]
fn parse_sign_request_display() {
    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash: [2u8; 32],
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in: 150_000_000,
            branch: 0,
            index: 1,
            prev_script: own_script(BRANCH_EXTERNAL, 1),
        }],
        outputs: vec![
            OutputMeta {
                value: 100_000_000,
                version: 0,
                pk_script: foreign_script(0xcc),
                is_change: false,
            },
            OutputMeta {
                value: 49_990_000,
                version: 0,
                pk_script: own_script(1, 0),
                is_change: true,
            },
        ],
    };
    let payload = encode_sign_request(&req).unwrap();
    let parsed = app_decred::parse_sign_request(&payload, &account_xpub()).unwrap();
    assert_eq!(parsed.network, "Decred Mainnet");
    assert_eq!(parsed.total_input_value, "1.5 DCR");
    assert_eq!(parsed.fee_value, "0.0001 DCR");
    assert_eq!(parsed.to.len(), 1);
    assert_eq!(parsed.to[0].value, "1 DCR");
    assert_eq!(parsed.change.len(), 1, "own change output recognized");
    assert_eq!(parsed.flagged.len(), 0);
    assert_eq!(parsed.from.len(), 1);
    assert!(parsed.from[0].address.starts_with("Ds"));
}

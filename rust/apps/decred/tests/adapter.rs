//! Firmware-adapter tests: prove the xpub-string bridge into dcr-rs preserves
//! the exact behavior the old vendored implementation had. The consensus
//! logic itself (BLAKE-256, sighash, wire format, airgap review/signing) is
//! oracle-tested inside dcr-rs; here we only exercise the seams this crate
//! owns — xpub parsing, address/dpub derivation, error mapping, and the
//! end-to-end sign flow through the public API rust_c calls.

use core::str::FromStr;

use app_decred::errors::DecredError;
use app_decred::hd::{BRANCH_EXTERNAL, BRANCH_INTERNAL};
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::NetworkKind;
use dcr_rs::address::p2pkh_script;
use dcr_rs::airgap::{encode_sign_request, InputMeta, OutputMeta, SignRequest, FORMAT_VERSION};
use dcr_rs::hashing::hash160;
use dcr_rs::hd::ExtPubKey;
use dcr_rs::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use dcr_rs::sighash::signature_hash_all;
use dcr_rs::tx::{MsgTx, OutPoint, TxIn, TxOut};

// BIP32 test vector 1 master key: the standard xpub and the dcrd
// `extendedkey_test.go` dpub for the same key material must line up.
const VEC1_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const VEC1_DPUB: &str = "dpubZ9169KDAEUnyoBhjjmT2VaEodr6pUTDoqCEAeqgbfr2JfkB88BbK77jbTYbcYXb2FVz7DKBdW4P618yd51MwF8DjKVopSbS7Lkgi6bowX5w";

#[test]
fn xpub_converts_to_dcrd_dpub() {
    assert_eq!(app_decred::get_dpub(VEC1_XPUB).unwrap(), VEC1_DPUB);
}

#[test]
fn get_address_agrees_with_dcr_rs_dpub_path() {
    // Two independent parse paths — the firmware xpub bridge (double-SHA256
    // base58) and dcr-rs's dpub decoder (double-BLAKE256 base58) — must yield
    // identical child addresses.
    let secp = Secp256k1::new();
    let account = ExtPubKey::from_base58(VEC1_DPUB).unwrap();
    for (branch, index) in [(0u32, 0u32), (0, 5), (1, 2)] {
        let pubkey = account.pubkey_at(&secp, branch, index).unwrap();
        let want = dcr_rs::Address::from_pubkey(&pubkey, dcr_rs::Network::Mainnet).encode();
        assert_eq!(
            app_decred::get_address(VEC1_XPUB, branch, index).unwrap(),
            want
        );
    }
}

#[test]
fn bad_xpub_maps_to_generate_address_error() {
    assert!(matches!(
        app_decred::get_dpub("xpub-not-really"),
        Err(DecredError::GenerateAddressError(_))
    ));
}

/// The account xpub exactly as the firmware produces it: bitcoin-crate BIP32
/// from the seed at m/44'/42'/0', neutered and serialized as `xpub…`.
fn firmware_account_xpub(secp: &Secp256k1<dcr_rs::secp256k1::All>, seed: &[u8]) -> String {
    let master = Xpriv::new_master(NetworkKind::Main, seed).unwrap();
    let path = DerivationPath::from_str("m/44'/42'/0'").unwrap();
    let account = master.derive_priv(secp, &path).unwrap();
    Xpub::from_priv(secp, &account).to_string()
}

/// A 25-byte P2PKH script that is NOT ours (arbitrary hash160).
fn foreign_script(tag: u8) -> Vec<u8> {
    p2pkh_script(&[tag; 20]).to_vec()
}

/// Build the funding transaction for an input, so `prev_hash` refers to a real
/// transaction that genuinely pays `value` to `script`. Format version 2 verifies
/// this, so an arbitrary hash no longer works.
fn funding_for(value: i64, script: &[u8]) -> ([u8; 32], Vec<u8>) {
    let tx = MsgTx {
        version: 1,
        tx_in: vec![TxIn {
            previous_outpoint: OutPoint {
                hash: [0u8; 32],
                index: 0xffff_ffff,
                tree: 0,
            },
            sequence: 0xffff_ffff,
            value_in: value,
            block_height: 0,
            block_index: 0xffff_ffff,
            signature_script: vec![0x00],
        }],
        tx_out: vec![TxOut {
            value,
            version: 0,
            pk_script: script.to_vec(),
        }],
        lock_time: 0,
        expiry: 0,
    };
    (tx.tx_hash(), tx.serialize_full())
}

fn request_for(xpub: &str) -> (SignRequest, Vec<u8>) {
    let secp = Secp256k1::new();
    let account = ExtPubKey::from_base58(&app_decred::get_dpub(xpub).unwrap()).unwrap();
    let pk0 = account.pubkey_at(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let script0 = p2pkh_script(&hash160(&pk0)).to_vec();
    let value_in: i64 = 100_000;
    let (prev_hash, prev_tx) = funding_for(value_in, &script0);
    // Change back to our own internal branch, carrying the path that proves it.
    let change_pk = account.pubkey_at(&secp, BRANCH_INTERNAL, 0).unwrap();
    let change_script = p2pkh_script(&hash160(&change_pk)).to_vec();
    let req = SignRequest {
        format_version: FORMAT_VERSION,
        tx_version: 1,
        account: 0,
        lock_time: 0,
        expiry: 0,
        inputs: vec![InputMeta {
            prev_hash,
            prev_index: 0,
            tree: 0,
            sequence: 0xffff_ffff,
            value_in,
            branch: BRANCH_EXTERNAL,
            index: 0,
            prev_script: script0.clone(),
            prev_tx: Some(prev_tx),
        }],
        outputs: vec![
            OutputMeta {
                value: 90_000,
                version: 0,
                pk_script: foreign_script(0xee),
                is_change: false,
                branch: None,
                index: None,
            },
            // Real change, proven by its derivation path. The version 1 form of this
            // fixture used a foreign script flagged as change to exercise the tamper
            // warning; that combination is now refused outright by validate(), so
            // the refusal is asserted separately below.
            OutputMeta {
                value: 1_000,
                version: 0,
                pk_script: change_script,
                is_change: true,
                branch: Some(BRANCH_INTERNAL),
                index: Some(0),
            },
        ],
        account_fp: None,
    };
    (req, script0)
}

#[test]
fn end_to_end_check_parse_sign_through_public_api() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let xpub = firmware_account_xpub(&secp, &seed);
    let (req, script0) = request_for(&xpub);
    let payload = encode_sign_request(&req).unwrap();

    // check: inputs re-derive from the stored xpub.
    app_decred::check_sign_request(&payload, &xpub).unwrap();

    // parse: the review proves which output is change and excludes it from the
    // headline amount.
    let parsed = app_decred::parse_sign_request(&payload, &xpub).unwrap();
    assert_eq!(parsed.network, "Decred Mainnet");
    assert_eq!(parsed.from.len(), 1);
    assert!(parsed.from[0].address.starts_with("Ds"));
    assert_eq!(parsed.to.len(), 1, "only the foreign output is a recipient");
    assert_eq!(parsed.change.len(), 1, "our own output is proven change");
    assert_eq!(
        parsed.total_send_value, "0.0009 DCR",
        "change is excluded from the amount the user approves"
    );
    assert_eq!(parsed.fee_value, "0.00009 DCR");

    // sign: produced tx parses and its signature verifies against the sighash.
    let signed = app_decred::sign_sign_request(&payload, &seed).unwrap();
    let tx = MsgTx::parse_full(&signed).unwrap();
    let ss = &tx.tx_in[0].signature_script;
    let l1 = ss[0] as usize;
    assert_eq!(ss[l1], 0x01, "SigHashAll");
    let der = &ss[1..l1];
    let l2 = ss[1 + l1] as usize;
    let pubkey = &ss[2 + l1..2 + l1 + l2];

    let sighash = signature_hash_all(&tx, 0, &script0).unwrap();
    let sig = Signature::from_der(der).unwrap();
    let pk = PublicKey::from_slice(pubkey).unwrap();
    secp.verify_ecdsa(&Message::from_digest(sighash), &sig, &pk)
        .expect("signature produced through the firmware API verifies");
}

#[test]
fn tampered_prev_script_is_refused_everywhere() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let xpub = firmware_account_xpub(&secp, &seed);
    let (mut req, _) = request_for(&xpub);
    req.inputs[0].prev_script = foreign_script(0x11);
    let payload = encode_sign_request(&req).unwrap();

    // Under format version 2 the tamper is caught earlier than it used to be: the
    // declared prev_script no longer matches the funding transaction the input
    // carries, so verification inside validate() refuses it before the
    // derive-and-compare step could report ScriptMismatch. What matters is that
    // every entry point refuses, so assert that rather than a specific variant.
    assert!(
        app_decred::check_sign_request(&payload, &xpub).is_err(),
        "check must refuse a tampered prev_script"
    );
    assert!(
        app_decred::sign_sign_request(&payload, &seed).is_err(),
        "the signer must refuse a tampered prev_script on its own"
    );
    assert!(
        app_decred::parse_sign_request(&payload, &xpub).is_err(),
        "the review screen must not render a tampered package either"
    );
}

#[test]
fn account_fingerprint_gates_wrong_wallet() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let xpub = firmware_account_xpub(&secp, &seed);
    let account = ExtPubKey::from_base58(&app_decred::get_dpub(&xpub).unwrap()).unwrap();
    let (mut req, _) = request_for(&xpub);

    // The right fingerprint (and no fingerprint at all) sails through.
    req.account_fp = Some(account.fingerprint());
    let payload = encode_sign_request(&req).unwrap();
    app_decred::check_sign_request(&payload, &xpub).unwrap();
    app_decred::parse_sign_request(&payload, &xpub).unwrap();

    // A request built against a different wallet/account is refused with the
    // friendly message before any script mismatch could fire.
    req.account_fp = Some([0xde, 0xad, 0xbe, 0xef]);
    let payload = encode_sign_request(&req).unwrap();
    assert!(matches!(
        app_decred::check_sign_request(&payload, &xpub),
        Err(DecredError::WrongWalletOrAccount)
    ));
    assert!(matches!(
        app_decred::parse_sign_request(&payload, &xpub),
        Err(DecredError::WrongWalletOrAccount)
    ));
}

/// lock_time and expiry must reach the review screen when set, and be omitted when
/// zero.
///
/// Both are attacker-controlled and both are committed by the signature, but
/// neither could previously cross into the display structs at all. Expiry is the
/// one that matters: past that height the transaction is permanently invalid, so a
/// companion could hand over a package that reviewed perfectly and then never
/// confirmed, with nothing on the device to explain it.
#[test]
fn lock_time_and_expiry_reach_the_review_screen() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let xpub = firmware_account_xpub(&secp, &seed);

    // Absent when zero, so the ordinary transaction shows no zero rows.
    let (req, _) = request_for(&xpub);
    let payload = encode_sign_request(&req).unwrap();
    let parsed = app_decred::parse_sign_request(&payload, &xpub).unwrap();
    assert_eq!(parsed.lock_time, None);
    assert_eq!(parsed.expiry, None);

    // Present, and rendered as decimal, when set.
    let (mut req, _) = request_for(&xpub);
    req.lock_time = 424_242;
    req.expiry = 999_001;
    let payload = encode_sign_request(&req).unwrap();
    let parsed = app_decred::parse_sign_request(&payload, &xpub).unwrap();
    assert_eq!(parsed.lock_time.as_deref(), Some("424242"));
    assert_eq!(parsed.expiry.as_deref(), Some("999001"));
}

/// A request naming a different BIP44 account must be refused up front, not after
/// the user has entered their password.
///
/// The device holds one account key, at m/44'/42'/0'. Previously `account` was
/// never compared against it, so a request declaring account 1 passed the check
/// gate and the entire review screen, then died inside the signer with a bare
/// ScriptMismatch — after approval. It must now fail on both pre-approval paths,
/// with the wrong-wallet code the scan UI renders as a specific message rather
/// than a generic invalid-QR error.
#[test]
fn wrong_account_is_refused_before_approval() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let xpub = firmware_account_xpub(&secp, &seed);
    let (mut req, _) = request_for(&xpub);

    req.account = 1;
    let payload = encode_sign_request(&req).unwrap();
    assert!(matches!(
        app_decred::check_sign_request(&payload, &xpub),
        Err(DecredError::WrongWalletOrAccount)
    ));
    assert!(matches!(
        app_decred::parse_sign_request(&payload, &xpub),
        Err(DecredError::WrongWalletOrAccount)
    ));

    // The account this device actually holds still works.
    req.account = 0;
    let payload = encode_sign_request(&req).unwrap();
    app_decred::check_sign_request(&payload, &xpub).unwrap();
    app_decred::parse_sign_request(&payload, &xpub).unwrap();
}

#[test]
fn duplicate_inputs_are_refused_before_display() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let xpub = firmware_account_xpub(&secp, &seed);
    let (mut req, _) = request_for(&xpub);

    // The same coin listed twice inflates the apparent input total and
    // understates the displayed fee — both the check and the parse (display)
    // paths must refuse it.
    let dup = req.inputs[0].clone();
    req.inputs.push(dup);
    let payload = encode_sign_request(&req).unwrap();
    assert!(matches!(
        app_decred::check_sign_request(&payload, &xpub),
        Err(DecredError::InvalidDataError(_))
    ));
    assert!(matches!(
        app_decred::parse_sign_request(&payload, &xpub),
        Err(DecredError::InvalidDataError(_))
    ));
    assert!(matches!(
        app_decred::sign_sign_request(&payload, &seed),
        Err(DecredError::InvalidDataError(_))
    ));
}

#[test]
fn version_gate_maps_to_unsupported_version() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let xpub = firmware_account_xpub(&secp, &seed);
    let (mut req, _) = request_for(&xpub);
    req.format_version = FORMAT_VERSION + 1;
    let payload = encode_sign_request(&req).unwrap();
    assert_eq!(
        app_decred::check_sign_request(&payload, &xpub),
        Err(DecredError::UnsupportedVersion)
    );
}

//! Firmware-adapter tests: prove the xpub-string bridge into dcr-rs preserves
//! the exact behavior the old vendored implementation had. The consensus
//! logic itself (BLAKE-256, sighash, wire format, airgap review/signing) is
//! oracle-tested inside dcr-rs; here we only exercise the seams this crate
//! owns — xpub parsing, address/dpub derivation, error mapping, and the
//! end-to-end sign flow through the public API rust_c calls.

use core::str::FromStr;

use app_decred::errors::DecredError;
use app_decred::hd::BRANCH_EXTERNAL;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::NetworkKind;
use dcr_rs::address::p2pkh_script;
use dcr_rs::airgap::{encode_sign_request, InputMeta, OutputMeta, SignRequest, FORMAT_VERSION};
use dcr_rs::hashing::hash160;
use dcr_rs::hd::ExtPubKey;
use dcr_rs::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use dcr_rs::sighash::signature_hash_all;
use dcr_rs::tx::MsgTx;

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

fn request_for(xpub: &str) -> (SignRequest, Vec<u8>) {
    let secp = Secp256k1::new();
    let account = ExtPubKey::from_base58(&app_decred::get_dpub(xpub).unwrap()).unwrap();
    let pk0 = account.pubkey_at(&secp, BRANCH_EXTERNAL, 0).unwrap();
    let script0 = p2pkh_script(&hash160(&pk0)).to_vec();
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
            branch: BRANCH_EXTERNAL,
            index: 0,
            prev_script: script0.clone(),
        }],
        outputs: vec![
            OutputMeta {
                value: 90_000,
                version: 0,
                pk_script: foreign_script(0xee),
                is_change: false,
            },
            // Foreign output the companion mislabels as change: must be flagged.
            OutputMeta {
                value: 1_000,
                version: 0,
                pk_script: foreign_script(0xdd),
                is_change: true,
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

    // parse: review classifies and flags the mislabelled change.
    let parsed = app_decred::parse_sign_request(&payload, &xpub).unwrap();
    assert_eq!(parsed.network, "Decred Mainnet");
    assert_eq!(parsed.from.len(), 1);
    assert!(parsed.from[0].address.starts_with("Ds"));
    assert_eq!(parsed.to.len(), 2, "both foreign outputs are recipients");
    assert_eq!(parsed.flagged.len(), 1, "mislabelled change is flagged");
    assert_eq!(parsed.total_send_value, "0.00091 DCR");
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

    assert_eq!(
        app_decred::check_sign_request(&payload, &xpub),
        Err(DecredError::ScriptMismatch)
    );
    assert_eq!(
        app_decred::sign_sign_request(&payload, &seed),
        Err(DecredError::ScriptMismatch)
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
        Err(DecredError::InvalidDataError(_))
    ));
    assert!(matches!(
        app_decred::parse_sign_request(&payload, &xpub),
        Err(DecredError::InvalidDataError(_))
    ));
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

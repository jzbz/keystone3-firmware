//! Reference vectors lifted verbatim from dcrd source. These are the oracle:
//! if app_decred disagrees with any of them, app_decred is wrong, because
//! these exact strings/bytes are what the live network produced and validated.
//!
//! Sources (paths are within the dcrd repo):
//!   - hdkeychain/extendedkey_test.go  (BIP32 dpub strings)
//!   - txscript/standard_test.go / stdaddr  (P2PKH address + payScript)
//!   - crypto/blake256                 (BLAKE-256 KATs)

use app_decred::address::{decode_p2pkh, p2pkh_script, PKH_ADDR_ID_MAINNET};
use app_decred::blake256;
use app_decred::hashing::check_encode;

// ---------------------------------------------------------------------------
// BLAKE-256 — Decred's universal hash. NOT BLAKE2/BLAKE3.
// ---------------------------------------------------------------------------

#[test]
fn blake256_empty_kat() {
    // dcrd: blake256.Sum256("")
    let got = blake256::sum256(b"");
    assert_eq!(
        hex::encode(got),
        "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"
    );
}

#[test]
fn blake256_single_zero_kat() {
    // dcrd: blake256.Sum256(0x00)
    let got = blake256::sum256(&[0x00]);
    assert_eq!(
        hex::encode(got),
        "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87"
    );
}

// ---------------------------------------------------------------------------
// Mainnet P2PKH addresses (base58check w/ double-BLAKE256 checksum, "Ds"
// prefix) and the canonical payScript: DUP HASH160 <20> EQUALVERIFY CHECKSIG.
// ---------------------------------------------------------------------------

#[test]
fn p2pkh_address_from_hash160() {
    let h160 = hex::decode("2789d58cfa0957d206f025c2af056fc8a77cebb0").unwrap();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&h160);
    let addr = check_encode(&arr, PKH_ADDR_ID_MAINNET);
    assert_eq!(addr, "DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu");
}

#[test]
fn p2pkh_address_second_vector() {
    let h160 = hex::decode("229ebac30efd6a69eec9c1a48e048b7c975c25f2").unwrap();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&h160);
    let addr = check_encode(&arr, PKH_ADDR_ID_MAINNET);
    assert_eq!(addr, "DsU7xcg53nxaKLLcAUSKyRndjG78Z2VZnX9");
}

#[test]
fn p2pkh_address_roundtrip_decode() {
    let h160 = hex::decode("2789d58cfa0957d206f025c2af056fc8a77cebb0").unwrap();
    let decoded = decode_p2pkh("DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu").unwrap();
    assert_eq!(&decoded[..], &h160[..]);
}

#[test]
fn p2pkh_payscript_layout() {
    let h160 = hex::decode("2789d58cfa0957d206f025c2af056fc8a77cebb0").unwrap();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&h160);
    let script = p2pkh_script(&arr);
    // dcrd: 76a914<20-byte-hash>88ac
    assert_eq!(
        hex::encode(script),
        "76a9142789d58cfa0957d206f025c2af056fc8a77cebb088ac"
    );
}

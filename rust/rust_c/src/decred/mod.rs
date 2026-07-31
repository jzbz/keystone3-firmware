pub mod structs;

use crate::common::{
    free::Free,
    structs::{SimpleResponse, TransactionCheckResult, TransactionParseResult},
    types::{Ptr, PtrBytes, PtrString, PtrT, PtrUR},
    ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT},
    utils::{convert_c_char, recover_c_char},
};
use crate::{extract_array, extract_array_mut};
use crate::{extract_ptr_with_type, make_free_method};
use alloc::string::ToString;
use cty::c_char;
use structs::DisplayDcrTx;
use ur_registry::decred::{dcr_sign_request::DcrSignRequest, dcr_signed_tx::DcrSignedTx};
use ur_registry::traits::RegistryItem;
use zeroize::Zeroize;

use app_decred::hd::BRANCH_EXTERNAL;

#[no_mangle]
pub unsafe extern "C" fn dcr_get_address(
    xpub: PtrString,
    index: u32,
) -> *mut SimpleResponse<c_char> {
    let xpub = recover_c_char(xpub);
    match app_decred::get_address(&xpub, BRANCH_EXTERNAL, index) {
        Ok(address) => SimpleResponse::success(convert_c_char(address)).simple_c_ptr(),
        Err(e) => SimpleResponse::from(e).simple_c_ptr(),
    }
}

/// Derive the Decred account extended public key from the seed.
///
/// Decred must not go through the shared `get_extended_pubkey_by_seed`: that helper
/// implements strict BIP32, while Decred's hardened derivation strips leading zero
/// bytes from the child private key, as dcrd's hdkeychain and dcrwallet do. The two
/// disagree for roughly one seed in 112, which would leave the stored xpub -- and so
/// the receive screen and the exported dpub -- describing a different wallet from
/// the one `sign_dcr_tx` derives from the same seed.
///
/// `path` is accepted for symmetry with the generic helper and to keep the account
/// index declarative in `account_public_info.c`; only `M/44'/42'/account'` is valid.
/// The returned string is standard BIP32 `xpub…` encoding of Decred-derived key
/// material, which is what the rest of the firmware parses.
#[no_mangle]
pub unsafe extern "C" fn dcr_get_extended_pubkey_by_seed(
    seed: PtrBytes,
    seed_len: u32,
    path: PtrString,
) -> *mut SimpleResponse<c_char> {
    let seed = extract_array!(seed, u8, seed_len as usize);
    let path = recover_c_char(path);
    let account = match app_decred::account_index_from_path(&path) {
        Ok(account) => account,
        Err(e) => return SimpleResponse::from(e).simple_c_ptr(),
    };
    match app_decred::get_account_xpub_by_seed(seed, account) {
        Ok(xpub) => SimpleResponse::success(convert_c_char(xpub)).simple_c_ptr(),
        Err(e) => SimpleResponse::from(e).simple_c_ptr(),
    }
}

/// The `dpub…` account export a watch-only Decred companion wallet imports.
#[no_mangle]
pub unsafe extern "C" fn dcr_get_dpub(xpub: PtrString) -> *mut SimpleResponse<c_char> {
    let xpub = recover_c_char(xpub);
    match app_decred::get_dpub(&xpub) {
        Ok(dpub) => SimpleResponse::success(convert_c_char(dpub)).simple_c_ptr(),
        Err(e) => SimpleResponse::from(e).simple_c_ptr(),
    }
}

/// Wallet-linking QR: a plain-text dpub the companion scans once.
#[no_mangle]
pub unsafe extern "C" fn get_connect_decred_wallet_ur(xpub: PtrString) -> *mut UREncodeResult {
    let xpub = recover_c_char(xpub);
    match app_decred::get_dpub(&xpub) {
        Ok(dpub) => UREncodeResult::text(dpub).c_ptr(),
        Err(e) => UREncodeResult::from(e).c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn check_dcr_tx(tx: PtrUR, xpub: PtrString) -> *mut TransactionCheckResult {
    let sign_request = extract_ptr_with_type!(tx, DcrSignRequest);
    let xpub = recover_c_char(xpub);
    match app_decred::check_sign_request(&sign_request.get_data(), &xpub) {
        Ok(_) => TransactionCheckResult::new().c_ptr(),
        Err(e) => TransactionCheckResult::from(e).c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn parse_dcr_tx(
    tx: PtrUR,
    xpub: PtrString,
) -> Ptr<TransactionParseResult<DisplayDcrTx>> {
    let sign_request = extract_ptr_with_type!(tx, DcrSignRequest);
    let xpub = recover_c_char(xpub);
    match app_decred::parse_sign_request(&sign_request.get_data(), &xpub) {
        Ok(parsed) => {
            TransactionParseResult::success(DisplayDcrTx::from(&parsed).c_ptr()).c_ptr()
        }
        Err(e) => TransactionParseResult::from(e).c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sign_dcr_tx(
    tx: PtrUR,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    let sign_request = extract_ptr_with_type!(tx, DcrSignRequest);
    let seed = extract_array_mut!(seed, u8, seed_len as usize);
    let result = match app_decred::sign_sign_request(&sign_request.get_data(), seed) {
        Ok(signed_tx) => match DcrSignedTx::new(signed_tx).try_into() {
            Err(e) => UREncodeResult::from(e).c_ptr(),
            Ok(v) => UREncodeResult::encode(
                v,
                DcrSignedTx::get_registry_type().get_type(),
                FRAGMENT_MAX_LENGTH_DEFAULT,
            )
            .c_ptr(),
        },
        Err(e) => UREncodeResult::from(e).c_ptr(),
    };
    seed.zeroize();
    result
}

make_free_method!(TransactionParseResult<DisplayDcrTx>);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    #[test]
    fn dcr_sign_request_ur_roundtrip() {
        // A dcr-sign-request UR must decode back to the same payload bytes and
        // route to the Decred view — the exact path a scanned QR takes.
        let payload: Vec<u8> = hex::decode("a1016d68656c6c6f20646563726564").unwrap();
        let cbor: Vec<u8> = DcrSignRequest::new(payload.clone()).try_into().unwrap();
        let encoded = ur_parse_lib::keystone_ur_encoder::probe_encode(
            &cbor,
            FRAGMENT_MAX_LENGTH_DEFAULT,
            DcrSignRequest::get_registry_type().get_type(),
        )
        .unwrap();
        assert!(!encoded.is_multi_part);
        assert!(encoded
            .data
            .to_lowercase()
            .starts_with("ur:dcr-sign-request/"));

        let decoded: ur_parse_lib::keystone_ur_decoder::URParseResult<DcrSignRequest> =
            ur_parse_lib::keystone_ur_decoder::probe_decode(encoded.data.to_lowercase()).unwrap();
        let request = decoded.data.unwrap();
        assert_eq!(request.get_data(), payload);
    }
}

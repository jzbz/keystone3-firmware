//! HD key derivation for Decred on Keystone.
//!
//! Path: `m / 44' / 42' / account' / branch / index`
//!   * coin type 42 (SLIP-0044, Decred)
//!   * branch 0 = external (receive), 1 = internal (change)
//!
//! BIP32 math is identical to Bitcoin (HMAC key `"Bitcoin seed"`); Decred only
//! differs in the `dprv`/`dpub` serialization version bytes and the
//! double-BLAKE256 base58 checksum. The firmware stores the account-level
//! extended public key in standard `xpub` form (see `account_public_info.c`),
//! so everything display-side derives from that xpub with public CKD and only
//! signing touches the seed.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::NetworkKind;

use crate::errors::{DecredError, Result};

pub const COIN_TYPE_DCR: u32 = 42;
pub const BRANCH_EXTERNAL: u32 = 0;
pub const BRANCH_INTERNAL: u32 = 1;

// Mainnet extended-key version bytes (dcrd `chaincfg/mainnetparams.go`).
pub const HD_PRIV_MAINNET: [u8; 4] = [0x02, 0xfd, 0xa4, 0xe8]; // dprv
pub const HD_PUB_MAINNET: [u8; 4] = [0x02, 0xfd, 0xa9, 0x26]; // dpub

/// The account-level derivation path the firmware registers for DCR.
pub fn account_path(account: u32) -> String {
    format!("m/44'/{}'/{}'", COIN_TYPE_DCR, account)
}

/// BIP32 master → `m/44'/42'/account'` private key from the wallet seed.
pub fn account_xprv_from_seed(secp: &Secp256k1<All>, seed: &[u8], account: u32) -> Result<Xpriv> {
    let master = Xpriv::new_master(NetworkKind::Main, seed)
        .map_err(|e| DecredError::SigningError(e.to_string()))?;
    let path = DerivationPath::from_str(&account_path(account))
        .map_err(|e| DecredError::SigningError(e.to_string()))?;
    master
        .derive_priv(secp, &path)
        .map_err(|e| DecredError::SigningError(e.to_string()))
}

/// `account'/branch/index` private key relative to an account xprv.
pub fn address_xprv(
    secp: &Secp256k1<All>,
    account: &Xpriv,
    branch: u32,
    index: u32,
) -> Result<Xpriv> {
    let path = [
        ChildNumber::from_normal_idx(branch)
            .map_err(|e| DecredError::SigningError(e.to_string()))?,
        ChildNumber::from_normal_idx(index)
            .map_err(|e| DecredError::SigningError(e.to_string()))?,
    ];
    account
        .derive_priv(secp, &path)
        .map_err(|e| DecredError::SigningError(e.to_string()))
}

/// Parse the stored account-level `xpub…` string.
pub fn parse_account_xpub(xpub: &str) -> Result<Xpub> {
    Xpub::from_str(xpub.trim())
        .map_err(|e| DecredError::GenerateAddressError(e.to_string()))
}

/// Compressed pubkey at `branch/index` below the account xpub (public CKD).
pub fn pubkey_from_xpub(
    secp: &Secp256k1<All>,
    account: &Xpub,
    branch: u32,
    index: u32,
) -> Result<[u8; 33]> {
    let path = [
        ChildNumber::from_normal_idx(branch)
            .map_err(|e| DecredError::GenerateAddressError(e.to_string()))?,
        ChildNumber::from_normal_idx(index)
            .map_err(|e| DecredError::GenerateAddressError(e.to_string()))?,
    ];
    let child = account
        .derive_pub(secp, &path)
        .map_err(|e| DecredError::GenerateAddressError(e.to_string()))?;
    Ok(child.public_key.serialize())
}

/// Re-serialize a standard `xpub…` as a Decred `dpub…`: same 78-byte BIP32
/// body, Decred version bytes, double-BLAKE256 base58 checksum. This is what a
/// watch-only Decred companion imports to track balances and build unsigned
/// transactions.
pub fn xpub_to_dpub(xpub: &str) -> Result<String> {
    let key = parse_account_xpub(xpub)?;
    let mut data = Vec::with_capacity(82);
    data.extend_from_slice(&HD_PUB_MAINNET);
    data.push(key.depth);
    data.extend_from_slice(key.parent_fingerprint.as_bytes());
    data.extend_from_slice(&u32::from(key.child_number).to_be_bytes());
    data.extend_from_slice(key.chain_code.as_bytes());
    data.extend_from_slice(&key.public_key.serialize());
    let cksum = crate::blake256::sum256d(&data);
    data.extend_from_slice(&cksum[..4]);
    Ok(bs58::encode(data).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP32 test vector 1 master key: the standard xpub and the dcrd
    // `extendedkey_test.go` dpub for the same key material must line up.
    const VEC1_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const VEC1_DPUB: &str = "dpubZ9169KDAEUnyoBhjjmT2VaEodr6pUTDoqCEAeqgbfr2JfkB88BbK77jbTYbcYXb2FVz7DKBdW4P618yd51MwF8DjKVopSbS7Lkgi6bowX5w";

    #[test]
    fn xpub_converts_to_dcrd_dpub() {
        assert_eq!(xpub_to_dpub(VEC1_XPUB).unwrap(), VEC1_DPUB);
    }

    #[test]
    fn seed_master_matches_bip32_vector1() {
        let secp = Secp256k1::new();
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();
        let xpub = Xpub::from_priv(&secp, &master);
        assert_eq!(xpub.to_string(), VEC1_XPUB);
    }
}

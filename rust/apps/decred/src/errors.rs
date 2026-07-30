use alloc::string::{String, ToString};
use thiserror;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, DecredError>;

#[derive(Error, Debug, PartialEq)]
pub enum DecredError {
    #[error("failed to generate decred address, {0}")]
    GenerateAddressError(String),
    #[error("invalid decred data: {0}")]
    InvalidDataError(String),
    #[error("failed to sign decred transaction, {0}")]
    SigningError(String),
    #[error("unsupported decred sign request version")]
    UnsupportedVersion,
    #[error("input index out of range")]
    SigHashIndex,
    #[error("input script does not match the wallet key (refusing to sign)")]
    ScriptMismatch,
    /// The request was built against a different wallet or a different BIP44
    /// account than the one this device holds. Maps to
    /// `ErrorCodes::MasterFingerprintMismatch`, which the scan UI whitelists for a
    /// specific "incongruent transaction" window — an `InvalidDataError` here would
    /// be downgraded to a generic "QR code not recognized".
    #[error("this transaction was built for a different wallet or account")]
    WrongWalletOrAccount,
}

/// Map dcr-rs errors onto the firmware error variants (which in turn map onto
/// C error codes in rust_c/src/common/errors.rs). The security-relevant
/// variants pass through one-to-one so the UI can show the precise refusal.
impl From<dcr_rs::Error> for DecredError {
    fn from(e: dcr_rs::Error) -> Self {
        match e {
            dcr_rs::Error::UnsupportedVersion => DecredError::UnsupportedVersion,
            dcr_rs::Error::SigHashIndex => DecredError::SigHashIndex,
            dcr_rs::Error::ScriptMismatch => DecredError::ScriptMismatch,
            dcr_rs::Error::Derivation | dcr_rs::Error::HardenedFromPublic => {
                DecredError::GenerateAddressError(e.to_string())
            }
            // Parse/Base58/BadChecksum/UnknownPrefix/Encode/InvalidRequest and
            // any future variants (dcr_rs::Error is non_exhaustive).
            other => DecredError::InvalidDataError(other.to_string()),
        }
    }
}

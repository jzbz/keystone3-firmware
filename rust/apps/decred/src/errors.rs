use alloc::string::String;
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
}

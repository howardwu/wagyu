use crate::derivation_path::DerivationPathError;

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    hash::Hash,
};

/// The interface for a generic format.
pub trait Format: Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

#[derive(Debug, Fail)]
pub enum FormatError {
    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    DerivationPathError(DerivationPathError),

    #[fail(display = "invalid address prefix: {:?}", _0)]
    InvalidPrefix(Vec<u8>),

    #[fail(display = "invalid version bytes: {:?}", _0)]
    InvalidVersionBytes(Vec<u8>),

    #[fail(display = "unsupported derivation path for the format: {}", _0)]
    UnsupportedDerivationPath(String),
}

impl From<DerivationPathError> for FormatError {
    fn from(error: DerivationPathError) -> Self {
        FormatError::DerivationPathError(error)
    }
}

impl From<base58_monero::base58::Error> for FormatError {
    fn from(error: base58_monero::base58::Error) -> Self {
        FormatError::Crate("base58_monero", format!("{:?}", error))
    }
}

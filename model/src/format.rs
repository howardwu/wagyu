use crate::derivation_path::DerivationPathError;

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    hash::Hash,
};

/// The interface for a generic format.
pub trait Format: Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error(transparent)]
    DerivationPathError(#[from] DerivationPathError),

    #[error("invalid address prefix: {0:?}")]
    InvalidPrefix(Vec<u8>),

    #[error("invalid version bytes: {0:?}")]
    InvalidVersionBytes(Vec<u8>),

    #[error("unsupported derivation path for the format: {0}")]
    UnsupportedDerivationPath(String),
}

impl From<base58_monero::base58::Error> for FormatError {
    fn from(error: base58_monero::base58::Error) -> Self {
        FormatError::Crate("base58_monero", format!("{:?}", error))
    }
}

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
};

/// The interface for a generic network.
pub trait Network: Copy + Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Ord + Sized + Hash {
    const NAME: &'static str;
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("invalid extended private key prefix: {0}")]
    InvalidExtendedPrivateKeyPrefix(String),

    #[error("invalid extended public key prefix: {0}")]
    InvalidExtendedPublicKeyPrefix(String),

    #[error("invalid network: {0}")]
    InvalidNetwork(String),
}

use crate::address::{Address, AddressError};
use crate::format::Format;
use crate::public_key::PublicKey;

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};
use rand::Rng;

/// The interface for a generic private key.
pub trait PrivateKey: Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized {
    type Address: Address;
    type Format: Format;
    type PublicKey: PublicKey;

    /// Returns a randomly-generated private key.
    fn new<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError>;

    /// Returns the public key of the corresponding private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

#[derive(Debug, thiserror::Error)]
pub enum PrivateKeyError {
    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error("invalid byte length: {0}")]
    InvalidByteLength(usize),

    #[error("invalid character length: {0}")]
    InvalidCharacterLength(usize),

    #[error("invalid private key checksum: {{ expected: {0:?}, found: {1:?} }}")]
    InvalidChecksum(String, String),

    #[error("invalid network: {{ expected: {0:?}, found: {1:?} }}")]
    InvalidNetwork(String, String),

    #[error("invalid private key prefix: {0:?}")]
    InvalidPrefix(Vec<u8>),

    #[error("{0}")]
    Message(String),

    #[error("unsupported format")]
    UnsupportedFormat,
}

impl From<crate::no_std::io::Error> for PrivateKeyError {
    fn from(error: crate::no_std::io::Error) -> Self {
        PrivateKeyError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<&'static str> for PrivateKeyError {
    fn from(msg: &'static str) -> Self {
        PrivateKeyError::Message(msg.into())
    }
}

impl From<base58::FromBase58Error> for PrivateKeyError {
    fn from(error: base58::FromBase58Error) -> Self {
        PrivateKeyError::Crate("base58", format!("{:?}", error))
    }
}

impl From<bech32::Error> for PrivateKeyError {
    fn from(error: bech32::Error) -> Self {
        PrivateKeyError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for PrivateKeyError {
    fn from(error: hex::FromHexError) -> Self {
        PrivateKeyError::Crate("hex", format!("{:?}", error))
    }
}

impl From<rand_core::Error> for PrivateKeyError {
    fn from(error: rand_core::Error) -> Self {
        PrivateKeyError::Crate("rand", format!("{:?}", error))
    }
}

impl From<libsecp256k1::Error> for PrivateKeyError {
    fn from(error: libsecp256k1::Error) -> Self {
        PrivateKeyError::Crate("libsecp256k1", format!("{:?}", error))
    }
}

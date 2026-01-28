use crate::address::{Address, AddressError};
use crate::derivation_path::{DerivationPath, DerivationPathError};
use crate::extended_public_key::ExtendedPublicKey;
use crate::format::Format;
use crate::network::NetworkError;
use crate::private_key::PrivateKey;
use crate::public_key::PublicKey;

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

/// The interface for a generic extended private key.
pub trait ExtendedPrivateKey: Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized {
    type Address: Address;
    type DerivationPath: DerivationPath;
    type ExtendedPublicKey: ExtendedPublicKey;
    type Format: Format;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    /// Returns a new extended private key.
    fn new(seed: &[u8], format: &Self::Format, path: &Self::DerivationPath) -> Result<Self, ExtendedPrivateKeyError>;

    /// Returns a new extended private key.
    fn new_master(seed: &[u8], format: &Self::Format) -> Result<Self, ExtendedPrivateKeyError>;

    /// Returns the extended private key of the given derivation path.
    fn derive(&self, path: &Self::DerivationPath) -> Result<Self, ExtendedPrivateKeyError>;

    /// Returns the extended public key of the corresponding extended private key.
    fn to_extended_public_key(&self) -> Self::ExtendedPublicKey;

    /// Returns the private key of the corresponding extended private key.
    fn to_private_key(&self) -> Self::PrivateKey;

    /// Returns the public key of the corresponding extended private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the address of the corresponding extended private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ExtendedPrivateKeyError {
    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error(transparent)]
    DerivationPathError(#[from] DerivationPathError),

    #[error("invalid byte length: {0}")]
    InvalidByteLength(usize),

    #[error("invalid extended private key checksum: {{ expected: {0:?}, found: {1:?} }}")]
    InvalidChecksum(String, String),

    #[error("invalid version bytes: {0:?}")]
    InvalidVersionBytes(Vec<u8>),

    #[error("maximum child depth reached: {0}")]
    MaximumChildDepthReached(u8),

    #[error("{0}")]
    Message(String),

    #[error(transparent)]
    NetworkError(#[from] NetworkError),

    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
}

impl From<crate::no_std::io::Error> for ExtendedPrivateKeyError {
    fn from(error: crate::no_std::io::Error) -> Self {
        ExtendedPrivateKeyError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<base58::FromBase58Error> for ExtendedPrivateKeyError {
    fn from(error: base58::FromBase58Error) -> Self {
        ExtendedPrivateKeyError::Crate("base58", format!("{:?}", error))
    }
}

impl From<bech32::Error> for ExtendedPrivateKeyError {
    fn from(error: bech32::Error) -> Self {
        ExtendedPrivateKeyError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<core::array::TryFromSliceError> for ExtendedPrivateKeyError {
    fn from(error: core::array::TryFromSliceError) -> Self {
        ExtendedPrivateKeyError::Crate("core::array", format!("{:?}", error))
    }
}

impl From<core::num::ParseIntError> for ExtendedPrivateKeyError {
    fn from(error: core::num::ParseIntError) -> Self {
        ExtendedPrivateKeyError::Crate("core::num", format!("{:?}", error))
    }
}

impl From<crypto_mac::InvalidKeyLength> for ExtendedPrivateKeyError {
    fn from(error: crypto_mac::InvalidKeyLength) -> Self {
        ExtendedPrivateKeyError::Crate("crypto-mac", format!("{:?}", error))
    }
}

impl From<libsecp256k1::Error> for ExtendedPrivateKeyError {
    fn from(error: libsecp256k1::Error) -> Self {
        ExtendedPrivateKeyError::Crate("libsecp256k1", format!("{:?}", error))
    }
}

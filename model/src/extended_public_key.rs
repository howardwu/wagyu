use crate::address::{Address, AddressError};
use crate::derivation_path::{DerivationPath, DerivationPathError};
use crate::extended_private_key::ExtendedPrivateKey;
use crate::format::Format;
use crate::network::NetworkError;
use crate::public_key::{PublicKey, PublicKeyError};

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

/// The interface for a generic extended public key.
pub trait ExtendedPublicKey: Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized {
    type Address: Address;
    type DerivationPath: DerivationPath;
    type ExtendedPrivateKey: ExtendedPrivateKey;
    type Format: Format;
    type PublicKey: PublicKey;

    /// Returns the extended public key of the corresponding extended private key.
    fn from_extended_private_key(extended_private_key: &Self::ExtendedPrivateKey) -> Self;

    /// Returns the extended public key for the given derivation path.
    fn derive(&self, path: &Self::DerivationPath) -> Result<Self, ExtendedPublicKeyError>;

    /// Returns the public key of the corresponding extended public key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the address of the corresponding extended public key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

#[derive(Debug, Fail)]
pub enum ExtendedPublicKeyError {
    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    DerivationPathError(DerivationPathError),

    #[fail(display = "invalid byte length: {}", _0)]
    InvalidByteLength(usize),

    #[fail(
        display = "invalid extended private key checksum: {{ expected: {:?}, found: {:?} }}",
        _0, _1
    )]
    InvalidChecksum(String, String),

    #[fail(display = "invalid child number: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidChildNumber(u32, u32),

    #[fail(display = "invalid version bytes: {:?}", _0)]
    InvalidVersionBytes(Vec<u8>),

    #[fail(display = "maximum child depth reached: {}", _0)]
    MaximumChildDepthReached(u8),

    #[fail(display = "{}", _0)]
    Message(String),

    #[fail(display = "{}", _0)]
    NetworkError(NetworkError),

    #[fail(display = "{}", _0)]
    PublicKeyError(PublicKeyError),

    #[fail(display = "unsupported format: {}", _0)]
    UnsupportedFormat(String),
}

impl From<crate::no_std::io::Error> for ExtendedPublicKeyError {
    fn from(error: crate::no_std::io::Error) -> Self {
        ExtendedPublicKeyError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<DerivationPathError> for ExtendedPublicKeyError {
    fn from(error: DerivationPathError) -> Self {
        ExtendedPublicKeyError::DerivationPathError(error)
    }
}

impl From<NetworkError> for ExtendedPublicKeyError {
    fn from(error: NetworkError) -> Self {
        ExtendedPublicKeyError::NetworkError(error)
    }
}

impl From<PublicKeyError> for ExtendedPublicKeyError {
    fn from(error: PublicKeyError) -> Self {
        ExtendedPublicKeyError::PublicKeyError(error)
    }
}

impl From<base58::FromBase58Error> for ExtendedPublicKeyError {
    fn from(error: base58::FromBase58Error) -> Self {
        ExtendedPublicKeyError::Crate("base58", format!("{:?}", error))
    }
}

impl From<bech32::Error> for ExtendedPublicKeyError {
    fn from(error: bech32::Error) -> Self {
        ExtendedPublicKeyError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<core::array::TryFromSliceError> for ExtendedPublicKeyError {
    fn from(error: core::array::TryFromSliceError) -> Self {
        ExtendedPublicKeyError::Crate("core::array", format!("{:?}", error))
    }
}

impl From<core::num::ParseIntError> for ExtendedPublicKeyError {
    fn from(error: core::num::ParseIntError) -> Self {
        ExtendedPublicKeyError::Crate("core::num", format!("{:?}", error))
    }
}

impl From<crypto_mac::InvalidKeyLength> for ExtendedPublicKeyError {
    fn from(error: crypto_mac::InvalidKeyLength) -> Self {
        ExtendedPublicKeyError::Crate("crypto-mac", format!("{:?}", error))
    }
}

impl From<secp256k1::Error> for ExtendedPublicKeyError {
    fn from(error: secp256k1::Error) -> Self {
        ExtendedPublicKeyError::Crate("libsecp256k1", format!("{:?}", error))
    }
}

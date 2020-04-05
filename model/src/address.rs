use crate::format::Format;
use crate::private_key::{PrivateKey, PrivateKeyError};
use crate::public_key::{PublicKey, PublicKeyError};

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
};

/// The interface for a generic address.
pub trait Address: 'static + Clone + Debug + Display + FromStr + Hash + PartialEq + Eq + Ord + Send + Sized + Sync {
    type Format: Format;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Result<Self, AddressError>;

    /// Returns the address corresponding to the given public key.
    fn from_public_key(public_key: &Self::PublicKey, format: &Self::Format) -> Result<Self, AddressError>;
}

#[derive(Debug, Fail)]
pub enum AddressError {
    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "invalid format conversion from {:?} to {:?}", _0, _1)]
    IncompatibleFormats(String, String),

    #[fail(display = "invalid address: {}", _0)]
    InvalidAddress(String),

    #[fail(display = "invalid byte length: {}", _0)]
    InvalidByteLength(usize),

    #[fail(display = "invalid character length: {}", _0)]
    InvalidCharacterLength(usize),

    #[fail(display = "invalid address checksum: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidChecksum(String, String),

    #[fail(display = "invalid network: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidNetwork(String, String),

    #[fail(display = "invalid address prefix: {:?}", _0)]
    InvalidPrefix(Vec<u8>),

    #[fail(display = "invalid address prefix length: {:?}", _0)]
    InvalidPrefixLength(usize),

    #[fail(display = "{}", _0)]
    Message(String),

    #[fail(display = "missing public spend key and/or public view key")]
    MissingPublicKey,

    #[fail(display = "{}", _0)]
    PrivateKeyError(PrivateKeyError),

    #[fail(display = "{}", _0)]
    PublicKeyError(PublicKeyError),
}

impl From<crate::no_std::io::Error> for AddressError {
    fn from(error: crate::no_std::io::Error) -> Self {
        AddressError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<crate::no_std::FromUtf8Error> for AddressError {
    fn from(error: crate::no_std::FromUtf8Error) -> Self {
        AddressError::Crate("crate::no_std", format!("{:?}", error))
    }
}

impl From<&'static str> for AddressError {
    fn from(msg: &'static str) -> Self {
        AddressError::Message(msg.into())
    }
}

impl From<PrivateKeyError> for AddressError {
    fn from(error: PrivateKeyError) -> Self {
        AddressError::PrivateKeyError(error)
    }
}

impl From<PublicKeyError> for AddressError {
    fn from(error: PublicKeyError) -> Self {
        AddressError::PublicKeyError(error)
    }
}

impl From<base58::FromBase58Error> for AddressError {
    fn from(error: base58::FromBase58Error) -> Self {
        AddressError::Crate("base58", format!("{:?}", error))
    }
}

impl From<base58_monero::base58::Error> for AddressError {
    fn from(error: base58_monero::base58::Error) -> Self {
        AddressError::Crate("base58_monero", format!("{:?}", error))
    }
}

impl From<bech32::Error> for AddressError {
    fn from(error: bech32::Error) -> Self {
        AddressError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<core::str::Utf8Error> for AddressError {
    fn from(error: core::str::Utf8Error) -> Self {
        AddressError::Crate("core::str", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for AddressError {
    fn from(error: hex::FromHexError) -> Self {
        AddressError::Crate("hex", format!("{:?}", error))
    }
}

impl From<rand_core::Error> for AddressError {
    fn from(error: rand_core::Error) -> Self {
        AddressError::Crate("rand", format!("{:?}", error))
    }
}

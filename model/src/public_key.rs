use crate::address::{Address, AddressError};
use crate::format::Format;
use crate::private_key::PrivateKey;

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

/// The interface for a generic public key.
pub trait PublicKey: Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized {
    type Address: Address;
    type Format: Format;
    type PrivateKey: PrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self;

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

#[derive(Debug, Fail)]
pub enum PublicKeyError {
    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "invalid byte length: {}", _0)]
    InvalidByteLength(usize),

    #[fail(display = "invalid character length: {}", _0)]
    InvalidCharacterLength(usize),

    #[fail(display = "invalid public key prefix: {:?}", _0)]
    InvalidPrefix(String),

    #[fail(display = "no public spending key found")]
    NoSpendingKey,

    #[fail(display = "no public viewing key found")]
    NoViewingKey,
}

impl From<crate::no_std::io::Error> for PublicKeyError {
    fn from(error: crate::no_std::io::Error) -> Self {
        PublicKeyError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<base58::FromBase58Error> for PublicKeyError {
    fn from(error: base58::FromBase58Error) -> Self {
        PublicKeyError::Crate("base58", format!("{:?}", error))
    }
}

impl From<bech32::Error> for PublicKeyError {
    fn from(error: bech32::Error) -> Self {
        PublicKeyError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for PublicKeyError {
    fn from(error: hex::FromHexError) -> Self {
        PublicKeyError::Crate("hex", format!("{:?}", error))
    }
}

impl From<secp256k1::Error> for PublicKeyError {
    fn from(error: secp256k1::Error) -> Self {
        PublicKeyError::Crate("libsecp256k1", format!("{:?}", error))
    }
}

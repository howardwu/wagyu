use crate::address::{Address, AddressError};
use crate::private_key::PrivateKey;

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

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

}

impl From<base58::FromBase58Error> for PublicKeyError {
    fn from(error: base58::FromBase58Error) -> Self {
        PublicKeyError::Crate("base58", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for PublicKeyError {
    fn from(error: hex::FromHexError) -> Self {
        PublicKeyError::Crate("hex", format!("{:?}", error))
    }
}

impl From<secp256k1::Error> for PublicKeyError {
    fn from(error: secp256k1::Error) -> Self {
        PublicKeyError::Crate("secp256k1", format!("{:?}", error))
    }
}

impl From<std::io::Error> for PublicKeyError {
    fn from(error: std::io::Error) -> Self {
        PublicKeyError::Crate("std::io", format!("{:?}", error))
    }
}

/// The interface for a generic public key.
pub trait PublicKey:
Clone
+ Debug
+ Display
+ FromStr
+ Send
+ Sync
+ 'static
+ Eq
+ Sized
{
    type Address: Address;
    type Format;
    type Network;
    type PrivateKey: PrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self;

    /// Returns the address of the corresponding private key.
    fn to_address(
        &self,
        format: &Self::Format,
        network: &Self::Network,
    ) -> Result<Self::Address, AddressError>;
}

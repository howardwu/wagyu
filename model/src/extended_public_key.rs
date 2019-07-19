use crate::address::{Address, AddressError};
use crate::public_key::{PublicKey, PublicKeyError};

use std::{fmt::{Debug, Display}, str::FromStr};
use crate::ExtendedPrivateKey;

/// The interface for a generic extended public key.
pub trait ExtendedPublicKey:
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
    type ExtendedPrivateKey: ExtendedPrivateKey;
    type Format;
    type Network;
    type PublicKey: PublicKey;

    /// Returns the extended public key of the corresponding extended private key.
    fn from_extended_private_key(private_key: &Self::ExtendedPrivateKey) -> Self;

    /// Returns the public key of the corresponding extended public key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the address of the corresponding extended public key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

#[derive(Debug, Fail)]
pub enum ExtendedPublicKeyError {

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "invalid byte length: {}", _0)]
    InvalidByteLength(usize),

    #[fail(display = "invalid extended private key checksum: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidChecksum(String, String),

    #[fail(display = "invalid child number: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidChildNumber(u32, u32),

    #[fail(display = "invalid derivation path: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidDerivationPath(String, String),

    #[fail(display = "invalid network bytes: {:?}", _0)]
    InvalidNetworkBytes(Vec<u8>),

    #[fail(display = "maximum child depth reached: {}", _0)]
    MaximumChildDepthReached(u8),

    #[fail(display = "{}", _0)]
    Message(String),

    #[fail(display = "{}", _0)]
    PublicKeyError(PublicKeyError),
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

impl From<crypto_mac::InvalidKeyLength> for ExtendedPublicKeyError {
    fn from(error: crypto_mac::InvalidKeyLength) -> Self {
        ExtendedPublicKeyError::Crate("crypto-mac", format!("{:?}", error))
    }
}

impl From<secp256k1::Error> for ExtendedPublicKeyError {
    fn from(error: secp256k1::Error) -> Self {
        ExtendedPublicKeyError::Crate("secp256k1", format!("{:?}", error))
    }
}

impl From<std::io::Error> for ExtendedPublicKeyError {
    fn from(error: std::io::Error) -> Self {
        ExtendedPublicKeyError::Crate("std::io", format!("{:?}", error))
    }
}

impl From<std::num::ParseIntError> for ExtendedPublicKeyError {
    fn from(error: std::num::ParseIntError) -> Self {
        ExtendedPublicKeyError::Crate("std::num", format!("{:?}", error))
    }
}

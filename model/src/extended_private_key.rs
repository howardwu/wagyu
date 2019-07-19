use crate::address::{Address, AddressError};
use crate::extended_public_key::ExtendedPublicKey;
use crate::private_key::PrivateKey;
use crate::public_key::PublicKey;

use crypto_mac;
use std::{fmt::{Debug, Display}, str::FromStr};
//use crate::PrivateKeyError;

#[derive(Debug, Fail)]
pub enum ExtendedPrivateKeyError {

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "invalid byte length: {}", _0)]
    InvalidByteLength(usize),

    #[fail(display = "invalid extended private key checksum: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidChecksum(String, String),

    #[fail(display = "invalid derivation path: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidDerivationPath(String, String),

    #[fail(display = "invalid network bytes: {:?}", _0)]
    InvalidNetworkBytes(Vec<u8>),

    #[fail(display = "maximum child depth reached: {}", _0)]
    MaximumChildDepthReached(u8),

    #[fail(display = "{}", _0)]
    Message(String),

}

impl From<base58::FromBase58Error> for ExtendedPrivateKeyError {
    fn from(error: base58::FromBase58Error) -> Self {
        ExtendedPrivateKeyError::Crate("base58", format!("{:?}", error))
    }
}

impl From<crypto_mac::InvalidKeyLength> for ExtendedPrivateKeyError {
    fn from(error: crypto_mac::InvalidKeyLength) -> Self {
        ExtendedPrivateKeyError::Crate("crypto-mac", format!("{:?}", error))
    }
}

impl From<secp256k1::Error> for ExtendedPrivateKeyError {
    fn from(error: secp256k1::Error) -> Self {
        ExtendedPrivateKeyError::Crate("secp256k1", format!("{:?}", error))
    }
}

impl From<std::io::Error> for ExtendedPrivateKeyError {
    fn from(error: std::io::Error) -> Self {
        ExtendedPrivateKeyError::Crate("std::io", format!("{:?}", error))
    }
}

impl From<std::num::ParseIntError> for ExtendedPrivateKeyError {
    fn from(error: std::num::ParseIntError) -> Self {
        ExtendedPrivateKeyError::Crate("std::num", format!("{:?}", error))
    }
}

/// The interface for a generic extended private key.
pub trait ExtendedPrivateKey:
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
    type ExtendedPublicKey: ExtendedPublicKey;
    type Format;
    type Network;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    /// Returns a new extended private key.
    fn new(seed: &[u8], network: &Self::Network) -> Result<Self, ExtendedPrivateKeyError>;

    /// Returns the extended public key of the corresponding extended private key.
    fn to_extended_public_key(&self) -> Self::ExtendedPublicKey;

    /// Returns the private key of the corresponding extended private key.
    fn to_private_key(&self) -> Self::PrivateKey;

    /// Returns the public key of the corresponding extended private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the address of the corresponding extended private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

use crate::address::{Address, AddressError};
use crate::private_key::PrivateKey;
use crate::public_key::{PublicKey, PublicKeyError};

use std::{fmt::Debug, hash::Hash};

/// The interface for a generic transactions.
pub trait Transaction: Clone + Debug + Send + Sync + 'static + Eq + Ord + Sized + Hash {
    type Address: Address;
    type Format;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;
}

#[derive(Debug, Fail)]
pub enum TransactionError {
    #[fail(display = "{}", _0)]
    AddressError(AddressError),

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "could not generate Edwards point from slice {:?}", _0)]
    EdwardsPointError([u8; 32]),

    #[fail(display = "insufficient information to craft transaction. missing: {}", _0)]
    InvalidInputs(String),

    #[fail(display = "invalid transaction id {:?}", _0)]
    InvalidTransactionId(usize),

    #[fail(display = "invalid chain id {:?}", _0)]
    InvalidChainId(u8),

    #[fail(display = "could not generate keys for key image")]
    KeyImageError,

    #[fail(display = "{}", _0)]
    Message(String),

    #[fail(display = "monero transaction error")]
    MoneroTransactionError,

    #[fail(display = "{}", _0)]
    PublicKeyError(PublicKeyError),
}

impl From<&'static str> for TransactionError {
    fn from(msg: &'static str) -> Self {
        TransactionError::Message(msg.into())
    }
}

impl From<AddressError> for TransactionError {
    fn from(error: AddressError) -> Self {
        TransactionError::AddressError(error)
    }
}

impl From<base58::FromBase58Error> for TransactionError {
    fn from(error: base58::FromBase58Error) -> Self {
        TransactionError::Crate("base58", format!("{:?}", error))
    }
}

impl From<base58_monero::base58::Error> for TransactionError {
    fn from(error: base58_monero::base58::Error) -> Self {
        TransactionError::Crate("base58_monero", format!("{:?}", error))
    }
}

impl From<bech32::Error> for TransactionError {
    fn from(error: bech32::Error) -> Self {
        TransactionError::Crate("hex", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for TransactionError {
    fn from(error: hex::FromHexError) -> Self {
        TransactionError::Crate("hex", format!("{:?}", error))
    }
}

impl From<PublicKeyError> for TransactionError {
    fn from(error: PublicKeyError) -> Self {
        TransactionError::PublicKeyError(error)
    }
}

impl From<secp256k1::Error> for TransactionError {
    fn from(error: secp256k1::Error) -> Self {
        TransactionError::Crate("secp256k1", format!("{:?}", error))
    }
}

impl From<std::io::Error> for TransactionError {
    fn from(error: std::io::Error) -> Self {
        TransactionError::Crate("std::io", format!("{:?}", error))
    }
}

impl From<uint::FromDecStrErr> for TransactionError {
    fn from(error: uint::FromDecStrErr) -> Self {
        TransactionError::Crate("uint", format!("{:?}", error))
    }
}

use crate::address::{Address, AddressError};
use crate::private_key::PrivateKey;
use crate::public_key::{PublicKey};
//use std::{fmt::{Debug, Display}, str::FromStr};

/// The interface for a generic private key.
pub trait Transaction:
//Clone
//+ Debug
//+ Send
//+ Sync
//+ 'static
//+ Eq
//+ Sized
{
    type Address: Address;
    type Format;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

}

#[derive(Debug, Fail)]
pub enum TransactionError {

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    Message(String),

    #[fail(display = "insufficient information to craft transaction. missing: {}", _0)]
    InvalidInputs(String),

    #[fail(display = "invalid transaction id {:?}", _0)]
    InvalidTransactionId(usize),

    #[fail(display = "invalid chain id {:?}", _0)]
    InvalidChainId(u8),

    #[fail(display = "{}", _0)]
    AddressError(AddressError),
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

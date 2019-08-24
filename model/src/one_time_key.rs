use crate::public_key::{PublicKeyError};
use crate::transaction::{TransactionError};

//use std::{
//    fmt::{Debug, Display},
//    str::FromStr,
//};

///// The interface for a generic one time public key.
//pub trait OneTimeKey: Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized {
//    type PublicKey: PublicKey;
//
//    /// Returns the address corresponding to the given public key.
//    fn new(public: &Self::PublicKey, rand: &[u8; 32], index: u64) -> Result<Self, OneTimeKeyError>;
//}

#[derive(Debug, Fail)]
pub enum OneTimeKeyError {
    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "could not generate Edwards point from slice {:?}", _0)]
    EdwardsPointError([u8; 32]),

    #[fail(display = "{}", _0)]
    PublicKeyError(PublicKeyError),

    #[fail(display = "{}", _0)]
    TransactionError(TransactionError),
//    #[fail(display = "invalid byte length: {}", _0)]
//    InvalidByteLength(usize),
//
//    #[fail(display = "invalid character length: {}", _0)]
//    InvalidCharacterLength(usize),
//
//    #[fail(display = "invalid public key prefix: {:?}", _0)]
//    InvalidPrefix(String),
}

impl From<PublicKeyError> for OneTimeKeyError {
    fn from(error: PublicKeyError) -> Self {
        OneTimeKeyError::PublicKeyError(error)
    }
}

impl From<TransactionError> for OneTimeKeyError {
    fn from(error: TransactionError) -> Self {
        OneTimeKeyError::TransactionError(error)
    }
}


//impl From<base58::FromBase58Error> for PublicKeyError {
//    fn from(error: base58::FromBase58Error) -> Self {
//        PublicKeyError::Crate("base58", format!("{:?}", error))
//    }
//}
//
//impl From<bech32::Error> for PublicKeyError {
//    fn from(error: bech32::Error) -> Self {
//        PublicKeyError::Crate("bech32", format!("{:?}", error))
//    }
//}
//
//impl From<hex::FromHexError> for PublicKeyError {
//    fn from(error: hex::FromHexError) -> Self {
//        PublicKeyError::Crate("hex", format!("{:?}", error))
//    }
//}
//
//impl From<secp256k1::Error> for PublicKeyError {
//    fn from(error: secp256k1::Error) -> Self {
//        PublicKeyError::Crate("secp256k1", format!("{:?}", error))
//    }
//}
//
//impl From<std::io::Error> for PublicKeyError {
//    fn from(error: std::io::Error) -> Self {
//        PublicKeyError::Crate("std::io", format!("{:?}", error))
//    }
//}

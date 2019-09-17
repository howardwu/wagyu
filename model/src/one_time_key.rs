use crate::public_key::{PublicKeyError};
use crate::transaction::{TransactionError};

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

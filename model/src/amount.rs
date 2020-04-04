use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    hash::Hash,
};

/// The interface for a generic amount.
pub trait Amount: Copy + Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

#[derive(Debug, Fail)]
pub enum AmountError {
    #[fail(display = "the amount: {} exceeds the supply bounds of {}", _0, _1)]
    AmountOutOfBounds(String, String),

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "invalid amount: {}", _0)]
    InvalidAmount(String),
}

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr
};

/// The interface for a generic derivation path.
pub trait DerivationPath: Copy + Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

#[derive(Debug, Fail)]
pub enum DerivationPathError {

    #[fail(display = "invalid child number: {}", _0)]
    InvalidChildNumber(u32),

    #[fail(display = "invalid child number format")]
    InvalidChildNumberFormat,

    #[fail(display = "invalid derivation path: {}", _0)]
    InvalidDerivationPath(String),
}


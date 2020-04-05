use crate::no_std::*;
use core::{fmt::Debug, hash::Hash};

/// The interface for a generic network.
pub trait Wordlist: Copy + Clone + Debug + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

#[derive(Debug, Fail)]
pub enum WordlistError {
    #[fail(display = "invalid index: {}", _0)]
    InvalidIndex(usize),

    #[fail(display = "invalid word: {}", _0)]
    InvalidWord(String),
}

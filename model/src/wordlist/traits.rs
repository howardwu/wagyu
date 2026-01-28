use crate::no_std::*;
use core::{fmt::Debug, hash::Hash};

/// The interface for a generic network.
pub trait Wordlist: Copy + Clone + Debug + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

#[derive(Debug, thiserror::Error)]
pub enum WordlistError {
    #[error("invalid index: {0}")]
    InvalidIndex(usize),

    #[error("invalid word: {0}")]
    InvalidWord(String),
}

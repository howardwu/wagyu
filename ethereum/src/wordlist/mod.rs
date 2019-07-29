use wagyu_model::wordlist::{Wordlist, WordlistError};

pub mod chinese_simplified;
pub use self::chinese_simplified::*;

pub mod chinese_traditional;
pub use self::chinese_traditional::*;

pub mod english;
pub use self::english::*;

pub mod french;
pub use self::french::*;

pub mod italian;
pub use self::italian::*;

pub mod japanese;
pub use self::japanese::*;

pub mod korean;
pub use self::korean::*;

pub mod spanish;
pub use self::spanish::*;

/// The interface for a Ethereum wordlist.
pub trait EthereumWordlist: Wordlist {
    /// The wordlist in original form.
    const WORDLIST: &'static str;

    /// Returns the word of a given index from the word list.
    fn get(index: usize) -> Result<String, WordlistError> {
        if index >= 2048 {
            return Err(WordlistError::InvalidIndex(index));
        }
        Ok(Self::get_all()[index].into())
    }

    /// Returns the index of a given word from the word list.
    fn get_index(word: &str) -> Result<usize, WordlistError> {
        match Self::get_all().iter().position(|element| element == &word) {
            Some(index) => Ok(index),
            None => Err(WordlistError::InvalidWord(word.into())),
        }
    }

    /// Returns the word list as a string.
    fn get_all() -> Vec<&'static str> {
        Self::WORDLIST.lines().collect::<Vec<&str>>()
    }
}

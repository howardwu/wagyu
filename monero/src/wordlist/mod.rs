use wagyu_model::wordlist::{Wordlist, WordlistError};

pub mod chinese_simplified;
pub use self::chinese_simplified::*;

pub mod dutch;
pub use self::dutch::*;

pub mod english;
pub use self::english::*;

pub mod english_old;
pub use self::english_old::*;

pub mod esperanto;
pub use self::esperanto::*;

pub mod french;
pub use self::french::*;

pub mod german;
pub use self::german::*;

pub mod italian;
pub use self::italian::*;

pub mod japanese;
pub use self::japanese::*;

pub mod lojban;
pub use self::lojban::*;

pub mod portuguese;
pub use self::portuguese::*;

pub mod russian;
pub use self::russian::*;

pub mod spanish;
pub use self::spanish::*;

/// The interface for a Monero wordlist.
pub trait MoneroWordlist: Wordlist {
    /// The wordlist in original form.
    const WORDLIST: &'static str;
    /// The prefix length for computing the checksum.
    const PREFIX_LENGTH: usize;

    /// Returns the word of a given index from the word list.
    fn get(index: usize) -> Result<String, WordlistError> {
        if index >= 1626 {
            return Err(WordlistError::InvalidIndex(index));
        }
        Ok(Self::get_all()[index].into())
    }

    /// Returns the index of a given word from the word list.
    fn get_index(word: &str) -> Result<usize, WordlistError> {
        match Self::get_all().iter().position(|e| e == &word) {
            Some(index) => Ok(index),
            None => Err(WordlistError::InvalidWord(word.into())),
        }
    }

    /// Returns the index of a given word from the word list.
    fn get_index_trimmed(word: &str) -> Result<usize, WordlistError> {
        match Self::get_all_trimmed().iter().position(|e| e == &word) {
            Some(index) => Ok(index),
            None => Err(WordlistError::InvalidWord(word.into())),
        }
    }

    /// Returns the word list as a string.
    fn get_all() -> Vec<&'static str> {
        Self::WORDLIST.lines().collect::<Vec<&str>>()
    }

    /// Returns the word list as a string.
    fn get_all_trimmed() -> Vec<String> {
        Self::get_all()
            .iter()
            .map(|word| word[0..Self::PREFIX_LENGTH].to_string())
            .collect()
    }
}

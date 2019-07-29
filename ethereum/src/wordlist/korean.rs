use crate::wordlist::EthereumWordlist;
use wagyu_model::{bip39::KOREAN, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Korean;

impl Wordlist for Korean {}

impl EthereumWordlist for Korean {
    /// The wordlist in original form.
    const WORDLIST: &'static str = KOREAN;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "껍질";
    const VALID_WORD_INDEX: usize = 283;
    const INVALID_WORD: &str = "a";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, Korean::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(Korean::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, Korean::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(Korean::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = Korean::get_all();
        assert_eq!(2048, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

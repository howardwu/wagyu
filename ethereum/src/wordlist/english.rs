use crate::wordlist::EthereumWordlist;
use wagyu_model::{bip39::ENGLISH, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct English;

impl Wordlist for English {}

impl EthereumWordlist for English {
    /// The wordlist in original form.
    const WORDLIST: &'static str = ENGLISH;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "deposit";
    const VALID_WORD_INDEX: usize = 472;
    const INVALID_WORD: &str = "abracadabra";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, English::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(English::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, English::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(English::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = English::get_all();
        assert_eq!(2048, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

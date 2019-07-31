use crate::wordlist::MoneroWordlist;
use wagyu_model::{monero::JAPANESE, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Japanese;

impl Wordlist for Japanese {}

impl MoneroWordlist for Japanese {
    /// The wordlist in original form.
    const WORDLIST: &'static str = JAPANESE;
    /// The prefix length for computing the checksum.
    const PREFIX_LENGTH: usize = 3;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "こうじ";
    const VALID_WORD_INDEX: usize = 608;
    const INVALID_WORD: &str = "a";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, Japanese::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(Japanese::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, Japanese::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(Japanese::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = Japanese::get_all();
        assert_eq!(1626, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

use crate::wordlist::MoneroWordlist;
use wagyu_model::{monero::ENGLISH, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct English;

impl Wordlist for English {}

impl MoneroWordlist for English {
    /// The wordlist in original form.
    const WORDLIST: &'static str = ENGLISH;
    /// The prefix length for computing the checksum.
    const PREFIX_LENGTH: usize = 3;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "magically";
    const VALID_WORD_INDEX: usize = 840;
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
        assert_eq!(1626, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

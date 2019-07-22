use crate::wordlist::MoneroWordlist;
use wagu_model::wordlist::Wordlist;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Russian;

impl Wordlist for Russian {}

impl MoneroWordlist for Russian {
    /// The wordlist in original form.
    const WORDLIST: &'static str = include_str!("./dictionary/russian.txt");
    /// The prefix length for computing the checksum.
    const PREFIX_LENGTH: usize = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "бабушка";
    const VALID_WORD_INDEX: usize = 93;
    const INVALID_WORD: &str = "a";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, Russian::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(Russian::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, Russian::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(Russian::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = Russian::get_all();
        assert_eq!(1626, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

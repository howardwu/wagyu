use crate::wordlist::MoneroWordlist;
use wagu_model::wordlist::Wordlist;

const PORTUGUESE: &str = include_str!("dictionary/portuguese.txt");

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Portuguese;

impl Wordlist for Portuguese {}

impl MoneroWordlist for Portuguese {
    /// Returns the word list as a string.
    fn get_all() -> Vec<&'static str> {
        PORTUGUESE.lines().collect::<Vec<&str>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "einsteiniano";
    const VALID_WORD_INDEX: usize = 417;
    const INVALID_WORD: &str = "a";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, Portuguese::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(Portuguese::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, Portuguese::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(Portuguese::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = Portuguese::get_all();
        assert_eq!(1626, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

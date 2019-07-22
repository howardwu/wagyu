use crate::wordlist::BitcoinWordlist;
use wagu_model::wordlist::Wordlist;

const CHINESE_TRADITIONAL: &str = include_str!("./bip39/chinese_traditional.txt");

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChineseTraditional;

impl Wordlist for ChineseTraditional {}

impl BitcoinWordlist for ChineseTraditional {
    /// Returns the word list as a string.
    fn get_all() -> Vec<&'static str> {
        CHINESE_TRADITIONAL.lines().collect::<Vec<&str>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "會";
    const VALID_WORD_INDEX: usize = 34;
    const INVALID_WORD: &str = "a";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, ChineseTraditional::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(ChineseTraditional::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, ChineseTraditional::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(ChineseTraditional::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = ChineseTraditional::get_all();
        assert_eq!(2048, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

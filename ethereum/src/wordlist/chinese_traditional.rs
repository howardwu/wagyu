use crate::wordlist::EthereumWordlist;
use wagyu_model::{bip39::CHINESE_TRADITIONAL, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChineseTraditional;

impl Wordlist for ChineseTraditional {}

impl EthereumWordlist for ChineseTraditional {
    /// The wordlist in original form.
    const WORDLIST: &'static str = CHINESE_TRADITIONAL;
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

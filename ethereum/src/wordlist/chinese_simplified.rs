use crate::wordlist::EthereumWordlist;
use wagyu_model::{bip39::CHINESE_SIMPLIFIED, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChineseSimplified;

impl Wordlist for ChineseSimplified {}

impl EthereumWordlist for ChineseSimplified {
    /// The wordlist in original form.
    const WORDLIST: &'static str = CHINESE_SIMPLIFIED;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "会";
    const VALID_WORD_INDEX: usize = 34;
    const INVALID_WORD: &str = "a";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, ChineseSimplified::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(ChineseSimplified::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, ChineseSimplified::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(ChineseSimplified::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = ChineseSimplified::get_all();
        assert_eq!(2048, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

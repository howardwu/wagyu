use crate::wordlist::EthereumWordlist;
use wagyu_model::{bip39::FRENCH, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct French;

impl Wordlist for French {}

impl EthereumWordlist for French {
    /// The wordlist in original form.
    const WORDLIST: &'static str = FRENCH;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "portique";
    const VALID_WORD_INDEX: usize = 1523;
    const INVALID_WORD: &str = "bonjour";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, French::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(French::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, French::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(French::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = French::get_all();
        assert_eq!(2048, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

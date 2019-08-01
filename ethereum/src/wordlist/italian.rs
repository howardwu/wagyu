use crate::wordlist::EthereumWordlist;
use wagyu_model::{bip39::ITALIAN, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Italian;

impl Wordlist for Italian {}

impl EthereumWordlist for Italian {
    /// The wordlist in original form.
    const WORDLIST: &'static str = ITALIAN;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "robusto";
    const VALID_WORD_INDEX: usize = 1496;
    const INVALID_WORD: &str = "gelato";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, Italian::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(Italian::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, Italian::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(Italian::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = Italian::get_all();
        assert_eq!(2048, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

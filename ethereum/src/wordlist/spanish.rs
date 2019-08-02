use crate::wordlist::EthereumWordlist;
use wagyu_model::{bip39::SPANISH, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Spanish;

impl Wordlist for Spanish {}

impl EthereumWordlist for Spanish {
    /// The wordlist in original form.
    const WORDLIST: &'static str = SPANISH;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "azúcar";
    const VALID_WORD_INDEX: usize = 207;
    const INVALID_WORD: &str = "hola";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        // Valid case
        assert_eq!(VALID_WORD, Spanish::get(VALID_WORD_INDEX).unwrap());
        // Invalid case
        assert!(Spanish::get(INVALID_WORD_INDEX).is_err());
    }

    #[test]
    fn get_index() {
        // Valid case
        assert_eq!(VALID_WORD_INDEX, Spanish::get_index(VALID_WORD).unwrap());
        // Invalid case
        assert!(Spanish::get_index(INVALID_WORD).is_err());
    }

    #[test]
    fn get_all() {
        let list = Spanish::get_all();
        assert_eq!(2048, list.len());
        assert_eq!(VALID_WORD, list[VALID_WORD_INDEX]);
    }
}

use wagu_model::mnemonic::MnemonicError;

use std::fs;

/// Mnemonic word languages
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum Language {
    CHINESE_SIMPLIFIED,
    CHINESE_TRADITIONAL,
    ENGLISH,
    FRENCH,
    ITALIAN,
    JAPANESE,
    KOREAN,
    SPANISH,
}

impl Language {
    /// Returns the word list for a given language as a string.
    pub fn get_wordlist(language: &Language) -> Result<String, MnemonicError> {
        match language {
            Language::CHINESE_SIMPLIFIED => Ok(fs::read_to_string("src/languages/chinese_simplified.txt")?),
            Language::CHINESE_TRADITIONAL => Ok(fs::read_to_string("src/languages/chinese_traditional.txt")?),
            Language::ENGLISH => Ok(fs::read_to_string("src/languages/english.txt")?),
            Language::FRENCH => Ok(fs::read_to_string("src/languages/french.txt")?),
            Language::ITALIAN => Ok(fs::read_to_string("src/languages/italian.txt")?),
            Language::JAPANESE => Ok(fs::read_to_string("src/languages/japanese.txt")?),
            Language::KOREAN => Ok(fs::read_to_string("src/languages/korean.txt")?),
            Language::SPANISH => Ok(fs::read_to_string("src/languages/spanish.txt")?),
        }
    }

    /// Returns the index of the given word in the language's word list.
    pub fn get_wordlist_index(word: &str, language: &Language) -> Result<usize, MnemonicError> {
        let word_string = Language::get_wordlist(language)?;
        match word_string.lines().position(|x| x == word) {
            Some(_) => Ok(index.unwrap()),
            None => Err(MnemonicError::InvalidWord(String::from(word)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "abandon";
    const INVALID_WORD: &str = "abandoz";

    #[test]
    fn get_wordlist_chinese_simplified() {
        assert!(Language::get_wordlist(&Language::CHINESE_SIMPLIFIED).is_ok());
    }

    #[test]
    fn get_wordlist_chinese_traditional() {
        assert!(Language::get_wordlist(&Language::CHINESE_TRADITIONAL).is_ok());
    }

    #[test]
    fn get_wordlist_english() {
        assert!(Language::get_wordlist(&Language::ENGLISH).is_ok());
    }

    #[test]
    fn get_wordlist_french() {
        assert!(Language::get_wordlist(&Language::FRENCH).is_ok());
    }

    #[test]
    fn get_wordlist_italian() {
        assert!(Language::get_wordlist(&Language::ITALIAN).is_ok());
    }

    #[test]
    fn get_wordlist_japanese() {
        assert!(Language::get_wordlist(&Language::JAPANESE).is_ok());
    }

    #[test]
    fn get_wordlist_korean() {
        assert!(Language::get_wordlist(&Language::KOREAN).is_ok());
    }

    #[test]
    fn get_wordlist_spanish() {
        assert!(Language::get_wordlist(&Language::SPANISH).is_ok());
    }

    #[test]
    fn get_valid_word() {
        assert!(Language::get_wordlist_index(VALID_WORD, &Language::ENGLISH).is_ok());
    }

    #[test]
    fn get_invalid_word() {
        assert!(Language::get_wordlist_index(INVALID_WORD, &Language::ENGLISH).is_err());
    }
}

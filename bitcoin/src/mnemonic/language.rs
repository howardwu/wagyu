use wagu_model::mnemonic::MnemonicError;

const CHINESE_SIMPLIFIED: &str = include_str!("./languages/chinese_simplified.txt");
const CHINESE_TRADITIONAL: &str = include_str!("./languages/chinese_traditional.txt");
const ENGLISH: &str = include_str!("./languages/english.txt");
const FRENCH: &str = include_str!("./languages/french.txt");
const ITALIAN: &str = include_str!("./languages/italian.txt");
const JAPANESE: &str = include_str!("./languages/japanese.txt");
const KOREAN: &str = include_str!("./languages/korean.txt");
const SPANISH: &str = include_str!("./languages/spanish.txt");

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
            Language::CHINESE_SIMPLIFIED => Ok(CHINESE_SIMPLIFIED.into()),
            Language::CHINESE_TRADITIONAL => Ok(CHINESE_TRADITIONAL.into()),
            Language::ENGLISH => Ok(ENGLISH.into()),
            Language::FRENCH => Ok(FRENCH.into()),
            Language::ITALIAN => Ok(ITALIAN.into()),
            Language::JAPANESE => Ok(JAPANESE.into()),
            Language::KOREAN => Ok(KOREAN.into()),
            Language::SPANISH => Ok(SPANISH.into()),
        }
    }

    /// Returns the index of the given word in the language's word list.
    pub fn get_wordlist_index(word: &str, language: &Language) -> Result<usize, MnemonicError> {
        let list = Language::get_wordlist(language)?;
        match list.lines().position(|s| s == word) {
            Some(index) => Ok(index),
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

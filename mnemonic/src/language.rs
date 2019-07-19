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

        let index = word_string.lines().position(|x| x == word);

        match index {
            Some(_) => Ok(index.unwrap()),
            None => Err(MnemonicError::InvalidWord(String::from(word)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_all_wordlists() {
        assert!(Language::get_wordlist(&Language::CHINESE_SIMPLIFIED).is_ok());
        assert!(Language::get_wordlist(&Language::CHINESE_TRADITIONAL).is_ok());
        assert!(Language::get_wordlist(&Language::ENGLISH).is_ok());
        assert!(Language::get_wordlist(&Language::FRENCH).is_ok());
        assert!(Language::get_wordlist(&Language::ITALIAN).is_ok());
        assert!(Language::get_wordlist(&Language::JAPANESE).is_ok());
        assert!(Language::get_wordlist(&Language::KOREAN).is_ok());
        assert!(Language::get_wordlist(&Language::SPANISH).is_ok());
    }
}
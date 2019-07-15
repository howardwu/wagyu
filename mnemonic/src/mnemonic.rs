
use sha2::{Digest, Sha256};

use std::fs;


const PBKDF2_ROUNDS: u32 = 2048;

/// Mnemonic word languages
#[allow(non_camel_case_types)]
pub enum Language {
    CHINESE_SIMPLIFIED,
    CHINESE_TRADITIONAL,
    ENGLISH,
    FRENCH,
    ITALIAN,
    JAPANESE,
    KOREAN,
    SPANISH
}

/// Represents a BIP39 Mnemonic
pub struct Mnemonic {

    /// Initial entropy for generating the mnemonic. Must be a multiple of 32 bits.
    pub entropy: Vec<u8>,

    /// Language of mnemnoic words
    pub language: Language,

    /// Mnemonic phrase
    pub phrase: String,
}

impl Mnemonic {
//    /// generates a new mnemonic with word_count words and optional password
//    pub fn new(word_count: u8, &language: Language, password: Option<&str>) -> Self {
//        assert word_count in [12, 15, 18, 21, 24]
//        let entropy : Vec<u8>;
//
//        Mnemonic::from_entropy(&entropy, language, password)
//    }

    /// derives a mnemonic from entropy and optional password
    pub fn from_entropy(entropy: &Vec<u8>, language: &Language, password: Option<&str>) {

//        let word_count = match entropy.len() {
//            16 => 12,
//            20 => 15,
//            24 => 18,
//            28 => 21,
//            32 => 24,
//            _ => panic!("Invalid entropy length")
//        };
//
//        println!("{}", word_count);
//
//        let word_string = match language {
//            Language::ENGLISH => fs::read_to_string("src/languages/english.txt").expect("Error reading file"),
//            _ => panic!("Invalid language")
//        };
//
//        let word_list : Vec<&str>= word_string.lines().collect();
//
//
//        println!("{}", word_list[0]);

        let mut hasher = Sha256::new();
        hasher.input(entropy);

        let checksum_byte = hasher.result()[0];

//        println!("{:?}", checksum_byte);

        let mut encoding_bits = entropy.clone();

        encoding_bits.push(checksum_byte);

        for x in &encoding_bits {
            println!{"{}", x};
        }

    }

//    /// derives a mnemonic from seed phrase
//    pub fn from_mnemonic(phrase: &str, language: &Language) -> Self {
//        Self {
//            entropy: Mnemonic::to_entropy(phrase, language),
//            language: *language,
//            phrase: String::from_str(phrase);
//        }
//    }
//
//    /// derives entropy from seed phrase
//    // TODO see https://github.com/trezor/python-mnemonic/blob/063a33b517803c88d81e0ff0ccc9587b833d8280/mnemonic/mnemonic.py#L126
//    pub fn to_entropy(phrase: &str, language: &Language) -> Vec<u8> { }
//
//    /// generates seed bytes from mnemonic
//    pub fn to_seed(&self) -> [u8; 64] { }
//
//    /// returns whether or not mnemonic phrase is valid
//    pub fn check_valid(phrase: &str, language: &Language) -> bool { }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_entropy() {
        let entropy: Vec<u8> =vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,];
        let _result = Mnemonic::from_entropy(&entropy, &Language::ENGLISH, None);
    }
}
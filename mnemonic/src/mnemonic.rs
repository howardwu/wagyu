
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
//    pub fn new(word_count: u8, language: Language, password: Option<&str>) -> Self { }
//
//    /// derives a mnemonic from entropy and optional password
//    pub fn from_entropy(entropy: &Vec<u8>, language: Language, password: Option<&str>) -> Self { }
//
//    /// derives a mnemonic from seed phrase
//    pub fn from_mnemonic(phrase: &str, language: Language) -> Self { }
//
//    /// generates seed bytes from mnemonic
//    pub fn to_seed(&self) -> [u8; 64] { }
}
use crate::address::{Address, AddressError};
use crate::extended_private_key::{ExtendedPrivateKey, ExtendedPrivateKeyError};
use crate::extended_public_key::ExtendedPublicKey;
use crate::format::Format;
use crate::private_key::{PrivateKey, PrivateKeyError};
use crate::public_key::PublicKey;
use crate::wordlist::WordlistError;

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};
use rand::Rng;

/// The interface for a generic mnemonic.
pub trait Mnemonic: Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized {
    type Address: Address;
    type Format: Format;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    /// Returns a new mnemonic.
    fn new<R: Rng>(rng: &mut R) -> Result<Self, MnemonicError>;

    /// Returns the mnemonic for the given phrase.
    fn from_phrase(phrase: &str) -> Result<Self, MnemonicError>;

    /// Returns the phrase of the corresponding mnemonic.
    fn to_phrase(&self) -> Result<String, MnemonicError>;

    /// Returns the private key of the corresponding mnemonic.
    fn to_private_key(&self, password: Option<&str>) -> Result<Self::PrivateKey, MnemonicError>;

    /// Returns the public key of the corresponding mnemonic.
    fn to_public_key(&self, password: Option<&str>) -> Result<Self::PublicKey, MnemonicError>;

    /// Returns the address of the corresponding mnemonic.
    fn to_address(&self, password: Option<&str>, format: &Self::Format) -> Result<Self::Address, MnemonicError>;
}

/// The interface for a generic mnemonic for extended keys.
pub trait MnemonicCount: Mnemonic {
    /// Returns a new mnemonic given the word count.
    fn new_with_count<R: Rng>(rng: &mut R, word_count: u8) -> Result<Self, MnemonicError>;
}

/// The interface for a generic mnemonic for extended keys.
pub trait MnemonicExtended: Mnemonic {
    type ExtendedPrivateKey: ExtendedPrivateKey;
    type ExtendedPublicKey: ExtendedPublicKey;

    /// Returns the extended private key of the corresponding mnemonic.
    fn to_extended_private_key(&self, password: Option<&str>) -> Result<Self::ExtendedPrivateKey, MnemonicError>;

    /// Returns the extended public key of the corresponding mnemonic.
    fn to_extended_public_key(&self, password: Option<&str>) -> Result<Self::ExtendedPublicKey, MnemonicError>;
}

#[derive(Debug, Fail)]
pub enum MnemonicError {
    #[fail(display = "{}", _0)]
    AddressError(AddressError),

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    ExtendedPrivateKeyError(ExtendedPrivateKeyError),

    #[fail(display = "Invalid checksum word: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidChecksumWord(String, String),

    #[fail(display = "Invalid decoding from word to seed")]
    InvalidDecoding,

    #[fail(display = "Invalid entropy length: {}", _0)]
    InvalidEntropyLength(usize),

    #[fail(display = "Invalid wordlist index: {}", _0)]
    InvalidIndex(usize),

    #[fail(display = "Invalid phrase: {}", _0)]
    InvalidPhrase(String),

    #[fail(display = "Invalid word not found in monero: {}", _0)]
    InvalidWord(String),

    #[fail(display = "Invalid mnemonic word count: {}", _0)]
    InvalidWordCount(u8),

    #[fail(display = "Missing the last word (checksum)")]
    MissingChecksumWord,

    #[fail(display = "Missing word(s) in mnemonic")]
    MissingWord,

    #[fail(display = "{}", _0)]
    PrivateKeyError(PrivateKeyError),

    #[fail(display = "{}", _0)]
    WordlistError(WordlistError),
}

impl From<crate::no_std::io::Error> for MnemonicError {
    fn from(error: crate::no_std::io::Error) -> Self {
        MnemonicError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<AddressError> for MnemonicError {
    fn from(error: AddressError) -> Self {
        MnemonicError::AddressError(error)
    }
}

impl From<ExtendedPrivateKeyError> for MnemonicError {
    fn from(error: ExtendedPrivateKeyError) -> Self {
        MnemonicError::ExtendedPrivateKeyError(error)
    }
}

impl From<PrivateKeyError> for MnemonicError {
    fn from(error: PrivateKeyError) -> Self {
        MnemonicError::PrivateKeyError(error)
    }
}

impl From<WordlistError> for MnemonicError {
    fn from(error: WordlistError) -> Self {
        MnemonicError::WordlistError(error)
    }
}

impl From<rand_core::Error> for MnemonicError {
    fn from(error: rand_core::Error) -> Self {
        MnemonicError::Crate("rand", format!("{:?}", error))
    }
}


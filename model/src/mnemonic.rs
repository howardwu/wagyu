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

#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    #[error(transparent)]
    AddressError(#[from] AddressError),

    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error(transparent)]
    ExtendedPrivateKeyError(#[from] ExtendedPrivateKeyError),

    #[error("Invalid checksum word: {{ expected: {0:?}, found: {1:?} }}")]
    InvalidChecksumWord(String, String),

    #[error("Invalid decoding from word to seed")]
    InvalidDecoding,

    #[error("Invalid entropy length: {0}")]
    InvalidEntropyLength(usize),

    #[error("Invalid wordlist index: {0}")]
    InvalidIndex(usize),

    #[error("Invalid phrase: {0}")]
    InvalidPhrase(String),

    #[error("Invalid word not found in monero: {0}")]
    InvalidWord(String),

    #[error("Invalid mnemonic word count: {0}")]
    InvalidWordCount(u8),

    #[error("Missing the last word (checksum)")]
    MissingChecksumWord,

    #[error("Missing word(s) in mnemonic")]
    MissingWord,

    #[error(transparent)]
    PrivateKeyError(#[from] PrivateKeyError),

    #[error(transparent)]
    WordlistError(#[from] WordlistError),
}

impl From<crate::no_std::io::Error> for MnemonicError {
    fn from(error: crate::no_std::io::Error) -> Self {
        MnemonicError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<rand_core::Error> for MnemonicError {
    fn from(error: rand_core::Error) -> Self {
        MnemonicError::Crate("rand", format!("{:?}", error))
    }
}

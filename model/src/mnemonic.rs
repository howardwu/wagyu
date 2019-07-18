
#[derive(Debug, Fail)]
pub enum MnemonicError {

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "Invalid mnemonic word count: {}", _0)]
    InvalidWordCount(u8),

    #[fail(display = "Invalid entropy length: {}", _0)]
    InvalidEntropyLength(usize),

    #[fail(display = "Invalid phrase: {}", _0)]
    InvalidPhrase(String),

    #[fail(display = "Invalid word not found in dictionary: {}", _0)]
    InvalidWord(String),

    #[fail(display = "Invalid language")]
    InvalidLanguage,

}

impl From<rand_core::Error> for MnemonicError {
    fn from(error: rand_core::Error) -> Self {
        MnemonicError::Crate("rand", format!("{:?}", error))
    }
}

impl From<std::io::Error> for MnemonicError {
    fn from(error: std::io::Error) -> Self {
        MnemonicError::Crate("std::io", format!("{:?}", error))
    }
}
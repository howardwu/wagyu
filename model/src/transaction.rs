use crate::address::{Address, AddressError};
use crate::extended_private_key::ExtendedPrivateKeyError;
use crate::format::Format;
use crate::private_key::{PrivateKey, PrivateKeyError};
use crate::public_key::PublicKey;

use rlp;

/// The interface for a generic transactions.
pub trait Transaction: Clone + Send + Sync + 'static {
    type Address: Address;
    type Amount;
    type Format: Format;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;
    type TransactionHash;
    type TransactionParameters;

    /// Returns an unsigned transaction given the receiver, amount, and parameters.
    fn new(
        receiver: &Self::Address,
        amount: &Self::Amount,
        parameters: &Self::TransactionParameters
    ) -> Result<Self, TransactionError>;

    /// Returns a signed transaction given the private key of the sender.
    fn sign(&self, private_key: &Self::PrivateKey) -> Result<Self, TransactionError>;

    /// Returns a transaction given the transaction bytes.
    fn from_transaction_bytes(transaction: &Vec<u8>) -> Result<Self, TransactionError>;

    /// Returns the transaction in bytes.
    fn to_transaction_bytes(&self) -> Result<Vec<u8>, TransactionError>;

    /// Returns the transaction hash.
    fn to_transaction_hash(&self) -> Result<Self::TransactionHash, TransactionError>;
}

#[derive(Debug, Fail)]
pub enum TransactionError {
    #[fail(display = "{}", _0)]
    AddressError(AddressError),

    #[fail(display = "invalid binding signature for the transaction")]
    InvalidBindingSig(),

    #[fail(display = "witnesses have a conflicting anchor")]
    ConflictingWitnessAnchors(),

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    ExtendedPrivateKeyError(ExtendedPrivateKeyError),

    #[fail(display = "Failed note decryption for enc_cyphertext: {}", _0)]
    FailedNoteDecryption(String),

    #[fail(display = "{}", _0)]
    Message(String),

    #[fail(display = "missing spend description")]
    MissingSpendDescription(),

    #[fail(display = "invalid ephemeral key {}", _0)]
    InvalidEphemeralKey(String),

    #[fail(display = "insufficient information to craft transaction. missing: {}", _0)]
    InvalidInputs(String),

    #[fail(display = "invalid output address: {}", _0)]
    InvalidOutputAddress(String),

    #[fail(display = "invalid ouptut description for address: {}", _0)]
    InvalidOutputDescription(String),

    #[fail(display = "invalid transaction RLP length: expected - 9, found - {:?}", _0)]
    InvalidRlpLength(usize),

    #[fail(display = "invalid script pub key for format: {}", _0)]
    InvalidScriptPubKey(String),

    #[fail(display = "invalid spend description for address")]
    InvalidSpendDescription,

    #[fail(display = "invalid transaction id {:?}", _0)]
    InvalidTransactionId(usize),

    #[fail(display = "invalid transaction - either both sender and signature should be present, or neither")]
    InvalidTransactionState,

    #[fail(display = "invalid chain id {:?}", _0)]
    InvalidChainId(u8),

    #[fail(display = "Null Error {:?}", _0)]
    NullError(()),

    #[fail(display = "{}", _0)]
    PrivateKeyError(PrivateKeyError),
}

impl From<&'static str> for TransactionError {
    fn from(msg: &'static str) -> Self {
        TransactionError::Message(msg.into())
    }
}

impl From<()> for TransactionError {
    fn from(error: ()) -> Self {
        TransactionError::NullError(error)
    }
}

impl From<AddressError> for TransactionError {
    fn from(error: AddressError) -> Self {
        TransactionError::AddressError(error)
    }
}

impl From<base58::FromBase58Error> for TransactionError {
    fn from(error: base58::FromBase58Error) -> Self {
        TransactionError::Crate("base58", format!("{:?}", error))
    }
}

impl From<bech32::Error> for TransactionError {
    fn from(error: bech32::Error) -> Self {
        TransactionError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<ExtendedPrivateKeyError> for TransactionError {
    fn from(error: ExtendedPrivateKeyError) -> Self {
        TransactionError::ExtendedPrivateKeyError(error)
    }
}

impl From<ff::PrimeFieldDecodingError> for TransactionError {
    fn from(error: ff::PrimeFieldDecodingError) -> Self {
        TransactionError::Crate("ff", format!("{:?}", error))
    }
}

impl From<hex::FromHexError> for TransactionError {
    fn from(error: hex::FromHexError) -> Self {
        TransactionError::Crate("hex", format!("{:?}", error))
    }
}

impl From<PrivateKeyError> for TransactionError {
    fn from(error: PrivateKeyError) -> Self {
        TransactionError::PrivateKeyError(error)
    }
}

impl From<rlp::DecoderError> for TransactionError {
    fn from(error: rlp::DecoderError) -> Self {
        TransactionError::Crate("rlp", format!("{:?}", error))
    }
}

impl From<secp256k1::Error> for TransactionError {
    fn from(error: secp256k1::Error) -> Self {
        TransactionError::Crate("secp256k1", format!("{:?}", error))
    }
}

impl From<std::io::Error> for TransactionError {
    fn from(error: std::io::Error) -> Self {
        TransactionError::Crate("std::io", format!("{:?}", error))
    }
}

impl From<uint::FromDecStrErr> for TransactionError {
    fn from(error: uint::FromDecStrErr) -> Self {
        TransactionError::Crate("uint", format!("{:?}", error))
    }
}

use crate::address::{Address, AddressError};
use crate::amount::AmountError;
use crate::extended_private_key::ExtendedPrivateKeyError;
use crate::format::Format;
use crate::private_key::{PrivateKey, PrivateKeyError};
use crate::public_key::PublicKey;

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    hash::Hash,
};
use rlp;

/// The interface for a generic transaction id.
pub trait TransactionId: Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash {}

/// The interface for a generic transactions.
pub trait Transaction: Clone + Send + Sync + 'static {
    type Address: Address;
    type Format: Format;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;
    type TransactionId: TransactionId;
    type TransactionParameters;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError>;

    /// Returns a signed transaction given the private key of the sender.
    fn sign(&self, private_key: &Self::PrivateKey) -> Result<Self, TransactionError>;

    /// Returns a transaction given the transaction bytes.
    fn from_transaction_bytes(transaction: &[u8]) -> Result<Self, TransactionError>;

    /// Returns the transaction in bytes.
    fn to_transaction_bytes(&self) -> Result<Vec<u8>, TransactionError>;

    /// Returns the transaction id.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error(transparent)]
    AddressError(#[from] AddressError),

    #[error(transparent)]
    AmountError(#[from] AmountError),

    #[error("witnesses have a conflicting anchor")]
    ConflictingWitnessAnchors(),

    #[error("{0}: {1}")]
    Crate(&'static str, String),

    #[error(transparent)]
    ExtendedPrivateKeyError(#[from] ExtendedPrivateKeyError),

    #[error("Failed note decryption for enc_cyphertext: {0}")]
    FailedNoteDecryption(String),

    #[error("invalid binding signature for the transaction")]
    InvalidBindingSig(),

    #[error("invalid chain id {0:?}")]
    InvalidChainId(u8),

    #[error("invalid ephemeral key {0}")]
    InvalidEphemeralKey(String),

    #[error("insufficient information to craft transaction. missing: {0}")]
    InvalidInputs(String),

    #[error("invalid output address: {0}")]
    InvalidOutputAddress(String),

    #[error("invalid ouptut description for address: {0}")]
    InvalidOutputDescription(String),

    #[error("invalid transaction RLP length: expected - 9, found - {0:?}")]
    InvalidRlpLength(usize),

    #[error("invalid script pub key for format: {0}")]
    InvalidScriptPubKey(String),

    #[error("invalid segwit flag: {0:?}")]
    InvalidSegwitFlag(usize),

    #[error("invalid spend description for address")]
    InvalidSpendDescription,

    #[error("invalid transaction id {0:?}")]
    InvalidTransactionId(usize),

    #[error("invalid transaction - either both sender and signature should be present, or neither")]
    InvalidTransactionState,

    #[error("invalid variable size integer: {0:?}")]
    InvalidVariableSizeInteger(usize),

    #[error("{0}")]
    Message(String),

    #[error("missing diversifier, check that the address is a Sapling address")]
    MissingDiversifier,

    #[error("missing outpoint address")]
    MissingOutpointAddress,

    #[error("missing outpoint amount")]
    MissingOutpointAmount,

    #[error("missing outpoint script public key")]
    MissingOutpointScriptPublicKey,

    #[error("missing output parameters")]
    MissingOutputParameters,

    #[error("missing spend description")]
    MissingSpendDescription,

    #[error("missing spend parameters")]
    MissingSpendParameters,

    #[error("Null Error {0:?}")]
    NullError(()),

    #[error(transparent)]
    PrivateKeyError(#[from] PrivateKeyError),

    #[error("Joinsplits are not supported")]
    UnsupportedJoinsplits,

    #[error("unsupported preimage operation on address format of {0}")]
    UnsupportedPreimage(String),
}

impl From<crate::no_std::io::Error> for TransactionError {
    fn from(error: crate::no_std::io::Error) -> Self {
        TransactionError::Crate("crate::no_std::io", format!("{:?}", error))
    }
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

impl From<base58::FromBase58Error> for TransactionError {
    fn from(error: base58::FromBase58Error) -> Self {
        TransactionError::Crate("base58", format!("{:?}", error))
    }
}

impl From<base58_monero::base58::Error> for TransactionError {
    fn from(error: base58_monero::base58::Error) -> Self {
        TransactionError::Crate("base58_monero", format!("{:?}", error))
    }
}

impl From<bech32::Error> for TransactionError {
    fn from(error: bech32::Error) -> Self {
        TransactionError::Crate("bech32", format!("{:?}", error))
    }
}

impl From<core::num::ParseIntError> for TransactionError {
    fn from(error: core::num::ParseIntError) -> Self {
        TransactionError::Crate("core::num", format!("{:?}", error))
    }
}

impl From<core::str::ParseBoolError> for TransactionError {
    fn from(error: core::str::ParseBoolError) -> Self {
        TransactionError::Crate("core::str", format!("{:?}", error))
    }
}

// Note: ff::PrimeFieldDecodingError was removed in newer versions of ff
// If needed, implement specific error handling for ff crate errors

impl From<hex::FromHexError> for TransactionError {
    fn from(error: hex::FromHexError) -> Self {
        TransactionError::Crate("hex", format!("{:?}", error))
    }
}

impl From<rlp::DecoderError> for TransactionError {
    fn from(error: rlp::DecoderError) -> Self {
        TransactionError::Crate("rlp", format!("{:?}", error))
    }
}

impl From<libsecp256k1::Error> for TransactionError {
    fn from(error: libsecp256k1::Error) -> Self {
        TransactionError::Crate("libsecp256k1", format!("{:?}", error))
    }
}

impl From<serde_json::error::Error> for TransactionError {
    fn from(error: serde_json::error::Error) -> Self {
        TransactionError::Crate("serde_json", format!("{:?}", error))
    }
}

impl From<uint::FromDecStrErr> for TransactionError {
    fn from(error: uint::FromDecStrErr) -> Self {
        TransactionError::Crate("uint", format!("{:?}", error))
    }
}

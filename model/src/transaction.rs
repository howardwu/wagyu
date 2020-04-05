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
    fn from_transaction_bytes(transaction: &Vec<u8>) -> Result<Self, TransactionError>;

    /// Returns the transaction in bytes.
    fn to_transaction_bytes(&self) -> Result<Vec<u8>, TransactionError>;

    /// Returns the transaction id.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError>;
}

#[derive(Debug, Fail)]
pub enum TransactionError {
    #[fail(display = "{}", _0)]
    AddressError(AddressError),

    #[fail(display = "{}", _0)]
    AmountError(AmountError),

    #[fail(display = "witnesses have a conflicting anchor")]
    ConflictingWitnessAnchors(),

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    ExtendedPrivateKeyError(ExtendedPrivateKeyError),

    #[fail(display = "Failed note decryption for enc_cyphertext: {}", _0)]
    FailedNoteDecryption(String),

    #[fail(display = "invalid binding signature for the transaction")]
    InvalidBindingSig(),

    #[fail(display = "invalid chain id {:?}", _0)]
    InvalidChainId(u8),

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

    #[fail(display = "invalid segwit flag: {:?}", _0)]
    InvalidSegwitFlag(usize),

    #[fail(display = "invalid spend description for address")]
    InvalidSpendDescription,

    #[fail(display = "invalid transaction id {:?}", _0)]
    InvalidTransactionId(usize),

    #[fail(display = "invalid transaction - either both sender and signature should be present, or neither")]
    InvalidTransactionState,

    #[fail(display = "invalid variable size integer: {:?}", _0)]
    InvalidVariableSizeInteger(usize),

    #[fail(display = "{}", _0)]
    Message(String),

    #[fail(display = "missing diversifier, check that the address is a Sapling address")]
    MissingDiversifier,

    #[fail(display = "missing outpoint address")]
    MissingOutpointAddress,

    #[fail(display = "missing outpoint amount")]
    MissingOutpointAmount,

    #[fail(display = "missing outpoint script public key")]
    MissingOutpointScriptPublicKey,

    #[fail(display = "missing output parameters")]
    MissingOutputParameters,

    #[fail(display = "missing spend description")]
    MissingSpendDescription,

    #[fail(display = "missing spend parameters")]
    MissingSpendParameters,

    #[fail(display = "Null Error {:?}", _0)]
    NullError(()),

    #[fail(display = "{}", _0)]
    PrivateKeyError(PrivateKeyError),

    #[fail(display = "Joinsplits are not supported")]
    UnsupportedJoinsplits,

    #[fail(display = "unsupported preimage operation on address format of {}", _0)]
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

impl From<AddressError> for TransactionError {
    fn from(error: AddressError) -> Self {
        TransactionError::AddressError(error)
    }
}

impl From<AmountError> for TransactionError {
    fn from(error: AmountError) -> Self {
        TransactionError::AmountError(error)
    }
}

impl From<ExtendedPrivateKeyError> for TransactionError {
    fn from(error: ExtendedPrivateKeyError) -> Self {
        TransactionError::ExtendedPrivateKeyError(error)
    }
}

impl From<PrivateKeyError> for TransactionError {
    fn from(error: PrivateKeyError) -> Self {
        TransactionError::PrivateKeyError(error)
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

#[cfg(feature = "ff")]
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

impl From<rlp::DecoderError> for TransactionError {
    fn from(error: rlp::DecoderError) -> Self {
        TransactionError::Crate("rlp", format!("{:?}", error))
    }
}

impl From<secp256k1::Error> for TransactionError {
    fn from(error: secp256k1::Error) -> Self {
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

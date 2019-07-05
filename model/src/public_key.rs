use address::Address;
use private_key::PrivateKey;
use utilities::bytes::{FromBytes, ToBytes};

use std::{fmt::{Debug, Display}, hash::Hash, str::FromStr};

/// The interface for a generic public key.
pub trait PublicKey:
//    ToBytes
//    + FromBytes
    Copy
    + Clone
    + Debug
    + Display
    + Send
    + Sync
    + 'static
    + Eq
    + Sized
    + Hash
{
    type Address: Address;
    type Format;
    type PrivateKey: PrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self;

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: Option<Self::Format>) -> Self::Address;
}

use address::Address;
use public_key::PublicKey;
use utilities::bytes::{FromBytes, ToBytes};

use std::{fmt::{Debug, Display}, hash::Hash, str::FromStr};

/// The interface for a generic private key.
pub trait PrivateKey:
//    ToBytes
//    + FromBytes
    Clone
    + Debug
    + Display
    + Default
    + FromStr
    + Send
    + Sync
    + 'static
    + Eq
    + Sized
{
    type Address: Address;
    type Format;
    type Network;
    type PublicKey: PublicKey;

    /// Returns a randomly-generated private key.
    fn new(network: Self::Network) -> Self;

    /// Returns the public key of the corresponding private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: Option<Self::Format>) -> Self::Address;
}

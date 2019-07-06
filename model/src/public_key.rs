use crate::address::Address;
use crate::private_key::PrivateKey;


use std::{
    fmt::{Debug, Display},
    hash::Hash,
};

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
    type Network;
    type PrivateKey: PrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self;

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format, network: &Self::Network) -> Self::Address;
}

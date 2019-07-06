use crate::address::Address;
use crate::public_key::PublicKey;


use std::{fmt::{Debug, Display}, str::FromStr};

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
    fn new(network: &Self::Network) -> Self;

    /// Returns the public key of the corresponding private key.
    fn to_public_key(&self) -> Self::PublicKey;

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format) -> Self::Address;
}

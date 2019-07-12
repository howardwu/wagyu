use crate::address::Address;
use crate::private_key::PrivateKey;

use std::{
    fmt::{Debug, Display},
    str::FromStr
};

/// The interface for a generic public key.
pub trait PublicKey:
//    ToBytes
//    + FromBytes
    Clone
    + Debug
    + Display
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
    type PrivateKey: PrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self;

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format, network: &Self::Network) -> Self::Address;
}

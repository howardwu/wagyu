use address::Address;
use public_key::PublicKey;
use utilities::bytes::{FromBytes, ToBytes};

use rand::Rng;
use std::{fmt::{Debug, Display}, hash::Hash, str::FromStr};

/// The interface for a generic private key.
pub trait PrivateKey<T>:
    ToBytes
    + FromBytes
    + Copy
    + Clone
    + Debug
    + Display
    + Default
    + Send
    + Sync
    + 'static
    + Eq
    + Rng
    + Sized
    + Hash
{
    /// Returns a randomly-generated private key.
    fn new(network: T) -> Self;

    /// Returns the network of the corresponding private key.
    fn network() -> T;

    /// Returns the public key of the corresponding private key.
    fn to_public_key<T: PublicKey>() -> T;

    /// Returns the address of the corresponding private key.
    fn to_address<T: Address>() -> T;
}

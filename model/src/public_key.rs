use address::Address;
use private_key::PrivateKey;
use utilities::bytes::{FromBytes, ToBytes};

use std::{fmt::{Debug, Display}, hash::Hash, str::FromStr};

/// The interface for a generic public key.
pub trait PublicKey:
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
    + Sized
    + Hash
{
    /// Returns the address corresponding to the given public key.
    fn from_private_key<T: PrivateKey>(private_key: &T) -> Self;

    /// Returns the address of the corresponding private key.
    fn to_address<T: Address>() -> T;
}

use private_key::PrivateKey;
use public_key::PublicKey;
use utilities::bytes::{FromBytes, ToBytes};

use std::{fmt::{Debug, Display}, hash::Hash, str::FromStr};

/// The interface for a generic address.
pub trait Address:
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
    /// Returns the address corresponding to the given private key.
    fn from_private_key<T: PrivateKey>(private_key: &T) -> Self;

    /// Returns the address corresponding to the given public key.
    fn from_public_key<T: PublicKey>(public_key: &T) -> Self;
}

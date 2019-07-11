use crate::private_key::PrivateKey;
use crate::public_key::PublicKey;

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr
};

/// The interface for a generic address.
pub trait Address:
    Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Ord + Sized + Hash
{
    type Format;
    type Network;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Self;

    /// Returns the address corresponding to the given public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
        network: &Self::Network
    ) -> Self;
}

use private_key::PrivateKey;
use public_key::PublicKey;

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
};

/// The interface for a generic address.
pub trait Address:
    Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash
{
    type Format;
    type Network;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: Option<Self::Format>) -> Self;

    /// Returns the address corresponding to the given public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        format: Option<Self::Format>,
        network: Option<Self::Network>
    ) -> Self;
}

use address::{MoneroAddress, Format};
use model::{Address, PublicKey};
use network::Network;
use private_key::MoneroPrivateKey;

/// Represents a Monero public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroPublicKey {

    /// The public viewing key
    pub public_view_key: [u8; 32],

    /// The public spending key
    pub public_spend_key: [u8; 32],
}

impl PublicKey for MoneroPublicKey {
    type Address = MoneroAddress;
    type Format = Format;
    type Network = Network;
    type PrivateKey = MoneroPrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self { }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: Option<Self::Format>, network: Option<Self::Network>) -> Self::Address {
        MoneroAddress::from_public_key(self, format, network)
    }
}


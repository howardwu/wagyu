use address::{MoneroAddress, Format};
use model::{Address, PrivateKey, PublicKey, crypto::checksum};
use network::{Network};
use public_key::MoneroPublicKey;

/// Represents a Monero private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MoneroPrivateKey {

    /// The private viewing key
    pub private_view_key: [u8; 32],

    /// The private spending key
    pub private_spend_key: [u8; 32],

    /// The network of the private key
    pub network: Network,
}

impl PrivateKey for MoneroPrivateKey {
    type Address = MoneroAddress;
    type Format = (Format, Network);
    type Network = Network;
    type PublicKey = MoneroPublicKey;

    /// Returns a randomly-generated Monero private key.
    fn new(network: Self::Network) -> Self { }

    /// Returns the public key of the corresponding Monero private key.
    fn to_public_key(&self) -> Self::PublicKey { }

    /// Returns the address of the corresponding Monero private key.
    fn to_address(&self, format: Option<Self::Format>) -> Self::Address { }
}
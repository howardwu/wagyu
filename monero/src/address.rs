use model::{Address, crypto::{checksum, hash160}, PrivateKey};
use network::{Network, MAINNET_ADDRESS_BYTE, TESTNET_ADDRESS_BYTE};
use private_key::MoneroPrivateKey;
use public_key::MoneroPublicKey;

use std::fmt;

/// Represents the format of a Monero address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Standard address format
    Standard
}

/// Represents a Monero address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroAddress {
    /// The Monero address
    pub address: String,

    /// The Network on which this address is usable
    pub network:Network,
}

impl Address for MoneroAddress {
    type Format = Format;
    type Network = Network;
    type PrivateKey = MoneroPrivateKey;
    type PublicKey = MoneroPublicKey;

    /// Returns the address corresponding to the given Monero private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: Option<Self::Format>) -> Self { }

    /// Returns the address corresponding to the given Bitcoin public key.
    fn from_public_key(public_key: &Self::PublicKey, format: Option<Self::Format>, network: Option<Self::Network>) -> Self { }
}

impl fmt::Display for MoneroAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

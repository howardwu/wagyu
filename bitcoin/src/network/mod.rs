use crate::address::Format;
use wagu_model::{AddressError, Network, PrivateKeyError};

pub mod mainnet;
pub use self::mainnet::*;

pub mod testnet;
pub use self::testnet::*;

/// The interface for a Bitcoin network.
pub trait BitcoinNetwork: Network {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &Format) -> Vec<u8>;

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError>;

    /// Returns the wif prefix of the given network.
    fn to_wif_prefix() -> u8;

    /// Returns the network of the given wif prefix.
    fn from_wif_prefix(prefix: u8) -> Result<Self, PrivateKeyError>;
}

use crate::address::Format;
use wagu_model::{AddressError, Network, NetworkError, PrivateKeyError};

pub mod mainnet;
pub use self::mainnet::*;

pub mod testnet;
pub use self::testnet::*;

/// The interface for a Zcash network.
pub trait ZcashNetwork: Network {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &Format) -> Vec<u8>;

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, AddressError>;

    /// Returns the wif prefix of the given network.
    fn to_wif_prefix() -> u8;

    /// Returns the network of the given wif prefix.
    fn from_wif_prefix(prefix: u8) -> Result<Self, PrivateKeyError>;

    /// Returns the extended private key prefix of the given network.
    fn to_extended_private_key_prefix() -> String;

    /// Returns the network of the given extended private key prefix.
    fn from_extended_private_key_prefix(prefix: &str) -> Result<Self, NetworkError>;

    /// Returns the extended public key prefix of the given network.
    fn to_extended_public_key_prefix() -> String;

    /// Returns the network of the given extended public key prefix.
    fn from_extended_public_key_prefix(prefix: &str) -> Result<Self, NetworkError>;

    /// Returns the coin type of the given network.
    fn to_coin_type() -> u8;

    /// Returns the network of the given coin type.
    fn from_coin_type(prefix: u8) -> Result<Self, NetworkError>;
}

use crate::format::ZcashFormat;
use wagyu_model::{AddressError, ChildIndex, Network, NetworkError, PrivateKeyError};

pub mod mainnet;
pub use self::mainnet::*;

pub mod testnet;
pub use self::testnet::*;

/// The interface for a Zcash network.
pub trait ZcashNetwork: Network {
    const HD_PURPOSE: ChildIndex = ChildIndex::Hardened(32);
    const HD_COIN_TYPE: ChildIndex;

    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &ZcashFormat) -> Vec<u8>;

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, AddressError>;

    /// Returns the WIF prefix of the given network.
    fn to_wif_prefix() -> u8;

    /// Returns the network of the given WIF prefix.
    fn from_wif_prefix(prefix: u8) -> Result<Self, PrivateKeyError>;

    /// Returns the network prefix for a Sprout spending key.
    fn to_sprout_spending_key_prefix() -> [u8; 2];

    /// Returns the network prefix for a Sprout viewing key.
    fn to_sprout_viewing_key_prefix() -> [u8; 3];

    /// Returns the Sapling spending key prefix of the given network.
    fn to_sapling_spending_key_prefix() -> String;

    /// Returns the Sapling viewing key prefix of the given network.
    fn to_sapling_viewing_key_prefix() -> String;

    /// Returns the extended private key prefix of the given network.
    fn to_extended_private_key_prefix() -> String;

    /// Returns the network of the given extended private key prefix.
    fn from_extended_private_key_prefix(prefix: &str) -> Result<Self, NetworkError>;

    /// Returns the extended public key prefix of the given network.
    fn to_extended_public_key_prefix() -> String;

    /// Returns the network of the given extended public key prefix.
    fn from_extended_public_key_prefix(prefix: &str) -> Result<Self, NetworkError>;
}

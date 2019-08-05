use super::*;
use crate::address::Format;
use wagyu_model::{AddressError, Network, NetworkError, PrivateKeyError};

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Mainnet;

impl Network for Mainnet {}

impl ZcashNetwork for Mainnet {
    const NAME: &'static str = "mainnet";

    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &Format) -> Vec<u8> {
        match format {
            Format::P2PKH => vec![0x1C, 0xB8],
            Format::P2SH => vec![0x1C, 0xBD],
            Format::Sprout => vec![0x16, 0x9A],
            Format::Sapling(_) => "zs".as_bytes().to_vec(),
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, AddressError> {
        if prefix.len() < 2 {
            return Err(AddressError::InvalidPrefixLength(prefix.len()));
        }

        match prefix[1] {
            0xB8 | 0xBD | 0x9A | 0x73 => Ok(Self),
            _ => return Err(AddressError::InvalidPrefix(prefix.clone())),
        }
    }

    /// Returns the WIF prefix of the given network.
    fn to_wif_prefix() -> u8 {
        0x80
    }

    /// Returns the network of the given WIF prefix.
    fn from_wif_prefix(prefix: u8) -> Result<Self, PrivateKeyError> {
        match prefix {
            0x80 => Ok(Self),
            _ => return Err(PrivateKeyError::InvalidPrefix(vec![prefix])),
        }
    }

    /// Returns the prefix for a Sprout spending key.
    fn to_sprout_spending_key_prefix() -> [u8; 2] {
        [0xAB, 0x36]
    }

    /// Returns the prefix for a Sprout viewing key.
    fn to_sprout_viewing_key_prefix() -> [u8; 3] {
        [0xA8, 0xAB, 0xD3]
    }

    /// Returns the Sapling spending key prefix of the given network.
    fn to_sapling_spending_key_prefix() -> String {
        "secret-spending-key-main".into()
    }

    /// Returns the Sapling viewing key prefix of the given network.
    fn to_sapling_viewing_key_prefix() -> String {
        "zviews".into()
    }

    /// Returns the extended private key prefix of the given network.
    fn to_extended_private_key_prefix() -> String {
        "secret-extended-key-main".into()
    }

    /// Returns the network of the given extended private key prefix.
    fn from_extended_private_key_prefix(prefix: &str) -> Result<Self, NetworkError> {
        match prefix {
            "secret-extended-key-main" => Ok(Self),
            _ => return Err(NetworkError::InvalidExtendedPrivateKeyPrefix(prefix.into())),
        }
    }

    /// Returns the extended public key prefix of the given network.
    fn to_extended_public_key_prefix() -> String {
        "zviews".into()
    }

    /// Returns the network of the given extended public key prefix.
    fn from_extended_public_key_prefix(prefix: &str) -> Result<Self, NetworkError> {
        match prefix {
            "zviews" => Ok(Self),
            _ => return Err(NetworkError::InvalidExtendedPublicKeyPrefix(prefix.into())),
        }
    }
}

impl FromStr for Mainnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Mainnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

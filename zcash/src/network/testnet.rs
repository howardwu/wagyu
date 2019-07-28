use super::*;
use crate::address::Format;
use wagu_model::{AddressError, Network, NetworkError, PrivateKeyError};

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Testnet;

impl Network for Testnet {}

impl ZcashNetwork for Testnet {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &Format) -> Vec<u8> {
        match format {
            Format::P2PKH => vec![0x1D, 0x25],
            Format::P2SH => vec![0x1C, 0xBA],
            Format::Sprout => vec![0x16, 0xB6],
            Format::Sapling(_) => "ztestsapling".as_bytes().to_vec(),
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, AddressError> {
        if prefix.len() < 2 {
            return Err(AddressError::InvalidPrefixLength(prefix.len()));
        }

        match prefix[1] {
            0x25 | 0xBA | 0xB6 | 0x74 => Ok(Self),
            _ => return Err(AddressError::InvalidPrefix(prefix.clone())),
        }
    }

    /// Returns the wif prefix of the given network.
    fn to_wif_prefix() -> u8 {
        0xEF
    }

    /// Returns the network of the given wif prefix.
    fn from_wif_prefix(prefix: u8) -> Result<Self, PrivateKeyError> {
        match prefix {
            0xEF => Ok(Self),
            _ => return Err(PrivateKeyError::InvalidPrefix(vec![prefix])),
        }
    }

    /// Returns the extended private key prefix of the given network.
    fn to_extended_private_key_prefix() -> String {
        "secret-extended-key-test".into()
    }

    /// Returns the network of the given extended private key prefix.
    fn from_extended_private_key_prefix(prefix: &str) -> Result<Self, NetworkError> {
        match prefix {
            "secret-extended-key-test" => Ok(Self),
            _ => return Err(NetworkError::InvalidExtendedPrivateKeyPrefix(prefix.into())),
        }
    }

    /// Returns the extended public key prefix of the given network.
    fn to_extended_public_key_prefix() -> String {
        "zviewtestsapling".into()
    }

    /// Returns the network of the given extended public key prefix.
    fn from_extended_public_key_prefix(prefix: &str) -> Result<Self, NetworkError> {
        match prefix {
            "zviewtestsapling" => Ok(Self),
            _ => return Err(NetworkError::InvalidExtendedPublicKeyPrefix(prefix.into())),
        }
    }
}

impl FromStr for Testnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "testnet" => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Testnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "testnet")
    }
}

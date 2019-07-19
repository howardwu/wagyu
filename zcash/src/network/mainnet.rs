use super::*;
use crate::address::Format;
use wagu_model::{AddressError, Network, NetworkError, PrivateKeyError};

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Mainnet;

impl Network for Mainnet {}

impl ZcashNetwork for Mainnet {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &Format) -> Vec<u8> {
        match format {
            Format::P2PKH => vec![0x1C, 0xB8],
            Format::P2SH => vec![0x1C, 0xBD],
            Format::Sprout => vec![0x16, 0x9A],
            Format::Sapling(_) => "zs".as_bytes().to_vec()
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, AddressError> {
        if prefix.len() < 2 {
            return Err(AddressError::InvalidPrefixLength(prefix.len()))
        }

        match prefix[1] {
            0xB8 | 0xBD | 0x9A | 0x73 => Ok(Self),
            _ => return Err(AddressError::InvalidPrefix(prefix.clone()))
        }
    }

    /// Returns the wif prefix of the given network.
    fn to_wif_prefix() -> u8 {
        0x80
    }

    /// Returns the network of the given wif prefix.
    fn from_wif_prefix(prefix: u8) -> Result<Self, PrivateKeyError> {
        match prefix {
            0x80 => Ok(Self),
            _ => return Err(PrivateKeyError::InvalidPrefix(vec![prefix]))
        }
    }
}

impl FromStr for Mainnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into()))
        }
    }
}

impl fmt::Display for Mainnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mainnet")
    }
}

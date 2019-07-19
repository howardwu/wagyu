use crate::address::Format;
use wagu_model::{AddressError, PrivateKeyError};

use serde::Serialize;
use std::fmt;

/// Represents the available networks on Zcash
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix(&self, format: &Format) -> Vec<u8> {
        format.to_address_prefix(&self)
    }

    /// Returns the network of the given address prefix.
    pub fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, AddressError> {
        if prefix.len() < 2 {
            return Err(AddressError::InvalidPrefixLength(prefix.len()))
        }

        match prefix[1] {
            0xB8 | 0xBD | 0x9A | 0x73 => Ok(Network::Mainnet),
            0x25 | 0xBA | 0xB6 | 0x74 => Ok(Network::Testnet),
            _ => return Err(AddressError::InvalidPrefix(prefix.clone()))
        }
    }

    /// Returns the wif prefix of the given network.
    pub fn to_wif_prefix(&self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet => 0xEF,
        }
    }

    /// Returns the network of the given wif prefix.
    pub fn from_wif_prefix(prefix: u8) -> Result<Self, PrivateKeyError> {
        match prefix {
            0x80 => Ok(Network::Mainnet),
            0xEF => Ok(Network::Testnet),
            _ => return Err(PrivateKeyError::InvalidPrefix(vec![prefix]))
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
        }
    }
}

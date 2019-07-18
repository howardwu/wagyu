use crate::address::Format;
use wagu_model::{AddressError, PrivateKeyError};

use serde::Serialize;
use std::fmt;

/// Represents the available networks on Bitcoin
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
    pub fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        match (prefix[0],prefix[1]) {
            (0x00, _) | (0x05, _) | (0x62, 0x63) => Ok(Network::Mainnet),
            (0x6F, _) | (0xC4, _) | (0x74, 0x62) => Ok(Network::Testnet),
            _ => return Err(AddressError::InvalidPrefix(prefix.to_owned()))
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

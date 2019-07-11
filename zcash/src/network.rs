use crate::address::Format;

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
    pub fn to_address_prefix(&self, format: &Format) -> [u8; 2] {
        format.to_address_prefix(&self)
    }

    /// Returns the network of the given address prefix.
    pub fn from_address_prefix(prefix: &[u8; 2]) -> Result<Self, &'static str> {
        match prefix {
            [0x1C, 0xB8] | [0x1C, 0xBD] | [0x16, 0x9A] => Ok(Network::Mainnet),
            [0x1D, 0x25] | [0x1C, 0xBA] | [0x16, 0xB6] => Ok(Network::Testnet),
            _ => return Err("invalid address prefix")
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
    pub fn from_wif_prefix(prefix: u8) -> Result<Self, &'static str> {
        match prefix {
            0x80 => Ok(Network::Mainnet),
            0xEF => Ok(Network::Testnet),
            _ => return Err("invalid wif prefix")
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::Mainnet => write!(f, "Mainnet"),
            Network::Testnet => write!(f, "Testnet"),
        }
    }
}

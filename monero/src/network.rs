use wagu_model::AddressError;

use serde::Serialize;
use std::fmt;

/// The Network enum represents the different types of Networks we can create MoneroWallets for.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
}

impl Network {
    /// Returns the address prefix of the given network.
    // TODO (howardwu): Account for formats other than standard.
    pub fn to_address_prefix(&self) -> u8 {
        match self {
            Network::Mainnet => 18,
            Network::Testnet => 24,
            Network::Stagenet => 53
        }
    }

    /// Returns the network of the given address prefix.
    pub fn from_address_prefix(prefix: u8) -> Result<Self, AddressError> {
        match prefix {
            18 | 19 | 42 => Ok(Network::Mainnet),
            24 | 25 | 36 => Ok(Network::Testnet),
            53 | 54 | 63 => Ok(Network::Stagenet),
            _ => return Err(AddressError::InvalidPrefix(vec![prefix]))
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Stagenet => write!(f, "stagenet"),
        }
    }
}

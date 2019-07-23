use super::*;
use crate::address::Format;
use wagu_model::{AddressError, Network, NetworkError};

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Testnet;

impl Network for Testnet {}

impl MoneroNetwork for Testnet {
    /// Returns the address prefix of the given network.
    /// https://github.com/monero-project/monero/blob/3ad4ecd4ff52f011ee94e0e80754b965b82f072b/src/cryptonote_config.h#L167&L169
    fn to_address_prefix(format: &Format) -> u8 {
        match format {
            Format::Standard => 53,
            Format::Integrated(_) => 54,
            Format::Subaddress => 63
        }
    }

    /// Returns the network of the given address prefix.
    /// https://github.com/monero-project/monero/blob/3ad4ecd4ff52f011ee94e0e80754b965b82f072b/src/cryptonote_config.h#L167&L169
    fn from_address_prefix(prefix: u8) -> Result<Self, AddressError> {
        match prefix {
            53 | 54 | 63 => Ok(Self),
            _ => Err(AddressError::InvalidPrefix(vec![prefix]))
        }
    }
}

impl FromStr for Testnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "testnet" => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into()))
        }
    }
}

impl fmt::Display for Testnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "testnet")
    }
}

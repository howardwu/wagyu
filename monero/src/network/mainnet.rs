use super::*;
use crate::address::Format;
use wagyu_model::{AddressError, Network, NetworkError};

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Mainnet;

impl Network for Mainnet {}

impl MoneroNetwork for Mainnet {
    const NAME: &'static str = "mainnet";

    /// Returns the address prefix of the given network.
    /// https://github.com/monero-project/monero/blob/3ad4ecd4ff52f011ee94e0e80754b965b82f072b/src/cryptonote_config.h#L153&L155
    fn to_address_prefix(format: &Format) -> u8 {
        match format {
            Format::Standard => 18,
            Format::Integrated(_) => 19,
            Format::Subaddress(_, _) => 42,
        }
    }

    /// Returns the network of the given address prefix.
    /// https://github.com/monero-project/monero/blob/3ad4ecd4ff52f011ee94e0e80754b965b82f072b/src/cryptonote_config.h#L153&L155
    fn from_address_prefix(prefix: u8) -> Result<Self, AddressError> {
        match prefix {
            18 | 19 | 42 => Ok(Self),
            _ => Err(AddressError::InvalidPrefix(vec![prefix])),
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

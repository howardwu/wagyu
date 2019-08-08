use super::*;
use crate::format::MoneroFormat;
use wagyu_model::{AddressError, Network, NetworkError};

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Testnet;

impl Network for Testnet {}

impl MoneroNetwork for Testnet {
    const NAME: &'static str = "testnet";

    /// Returns the address prefix of the given network.
    /// https://github.com/monero-project/monero/blob/3ad4ecd4ff52f011ee94e0e80754b965b82f072b/src/cryptonote_config.h#L167&L169
    fn to_address_prefix(format: &MoneroFormat) -> u8 {
        match format {
            MoneroFormat::Standard => 53,
            MoneroFormat::Integrated(_) => 54,
            MoneroFormat::Subaddress(_, _) => 63,
        }
    }

    /// Returns the network of the given address prefix.
    /// https://github.com/monero-project/monero/blob/3ad4ecd4ff52f011ee94e0e80754b965b82f072b/src/cryptonote_config.h#L167&L169
    fn from_address_prefix(prefix: u8) -> Result<Self, AddressError> {
        match prefix {
            53 | 54 | 63 => Ok(Self),
            _ => Err(AddressError::InvalidPrefix(vec![prefix])),
        }
    }
}

impl FromStr for Testnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Testnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

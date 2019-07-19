use super::*;
use crate::address::Format;
use wagu_model::{AddressError, Network, NetworkError, PrivateKeyError};

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Mainnet;

impl Network for Mainnet {}

impl BitcoinNetwork for Mainnet {
    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &Format) -> Vec<u8> {
        match format {
            Format::P2PKH => vec![0x00],
            Format::P2SH_P2WPKH => vec![0x05],
            Format::Bech32 => vec![0x62, 0x63]
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        match (prefix[0], prefix[1]) {
            (0x00, _) | (0x05, _) | (0x62, 0x63) => Ok(Self),
            _ => Err(AddressError::InvalidPrefix(prefix.to_owned()))
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
            _ => Err(PrivateKeyError::InvalidPrefix(vec![prefix]))
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

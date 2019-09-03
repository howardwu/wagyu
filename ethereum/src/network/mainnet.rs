use crate::network::EthereumNetwork;
use wagyu_model::{ChildIndex, Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an Ethereum main network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Mainnet;

impl Network for Mainnet {
    const NAME: &'static str = "mainnet";
}

impl EthereumNetwork for Mainnet {
    const CHAIN_ID: u32 = 1;
    const NETWORK_ID: u32 = 1;
    const HD_COIN_TYPE: ChildIndex = ChildIndex::Hardened(60);
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

use crate::network::EthereumNetwork;
use wagyu_model::{ChildIndex, Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an Ethereum test network (PoW).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Ropsten;

impl Network for Ropsten {
    const NAME: &'static str = "ropsten";
}

impl EthereumNetwork for Ropsten {
    const CHAIN_ID: u32 = 3;
    const NETWORK_ID: u32 = 3;
    const HD_COIN_TYPE: ChildIndex = ChildIndex::Hardened(1);
}

impl FromStr for Ropsten {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Ropsten {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

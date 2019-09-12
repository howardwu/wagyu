use crate::network::EthereumNetwork;
use wagyu_model::{ChildIndex, Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an Ethereum test network (PoA).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Kovan;

impl Network for Kovan {
    const NAME: &'static str = "kovan";
}

impl EthereumNetwork for Kovan {
    const CHAIN_ID: u32 = 42;
    const NETWORK_ID: u32 = 42;
    const HD_COIN_TYPE: ChildIndex = ChildIndex::Hardened(1);
}

impl FromStr for Kovan {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Kovan {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

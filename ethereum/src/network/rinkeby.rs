use crate::network::EthereumNetwork;
use wagyu_model::{ChildIndex, Network, NetworkError};

use serde::Serialize;
use std::{fmt, str::FromStr};

/// Represents an Ethereum test network (PoA).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Rinkeby;

impl Network for Rinkeby {
    const NAME: &'static str = "rinkeby";
}

impl EthereumNetwork for Rinkeby {
    const CHAIN_ID: u32 = 4;
    const NETWORK_ID: u32 = 4;
    const HD_COIN_TYPE: ChildIndex = ChildIndex::Hardened(1);
}

impl FromStr for Rinkeby {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Rinkeby {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

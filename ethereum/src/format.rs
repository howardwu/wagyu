use wagyu_model::Format;

use serde::Serialize;
use std::fmt;

/// Represents the format of a Ethereum address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EthereumFormat {
    Standard,
}

impl Format for EthereumFormat {}

impl fmt::Display for EthereumFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EthereumFormat")
    }
}

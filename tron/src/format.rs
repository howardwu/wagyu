use wagyu_model::Format;

use serde::Serialize;
use std::fmt;

/// Represents the format of a Tron address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TronFormat {
    Standard,
}

impl Format for TronFormat {}

impl fmt::Display for TronFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TronFormat")
    }
}

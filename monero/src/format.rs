use crate::network::MoneroNetwork;
use wagyu_model::{no_std::vec, AddressError, Format};

use core::fmt;
use serde::Serialize;

/// Represents the format of a Monero address
#[derive(Serialize, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MoneroFormat {
    /// Standard address
    Standard,
    /// Address with payment id (8 bytes)
    Integrated([u8; 8]),
    /// Subaddress
    Subaddress(u32, u32),
}

impl Format for MoneroFormat {}

impl MoneroFormat {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix<N: MoneroNetwork>(&self) -> u8 {
        N::to_address_prefix(self)
    }

    /// Returns the format of the given address.
    pub fn from_address(address: &[u8]) -> Result<Self, AddressError> {
        match address[0] {
            18 | 24 | 53 => Ok(MoneroFormat::Standard),
            19 | 25 | 54 => {
                let mut data = [0u8; 8];
                data.copy_from_slice(&address[65..73]);
                Ok(MoneroFormat::Integrated(data))
            }
            42 | 36 | 63 => Ok(MoneroFormat::Subaddress(u32::max_value(), u32::max_value())),
            _ => return Err(AddressError::InvalidPrefix(vec![address[0]])),
        }
    }
}

impl fmt::Display for MoneroFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MoneroFormat::Standard => write!(f, "standard"),
            MoneroFormat::Integrated(_) => write!(f, "integrated"),
            MoneroFormat::Subaddress(major, minor) => write!(f, "subaddress({},{})", major, minor),
        }
    }
}

use crate::network::ZcashNetwork;
use wagyu_model::{AddressError, Format};

use serde::Serialize;
use std::fmt;

/// Represents the format of a Zcash address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ZcashFormat {
    /// Pay-to-Pubkey Hash, transparent address beginning with "t1" or "tm"
    P2PKH,
    /// Pay-to-Script Hash, transparent address beginning with "t3" or "t2"
    P2SH,
    /// Sprout shielded address beginning with "zc" or "zt"
    Sprout,
    /// Sapling shielded address beginning with "zs" or "ztestsapling"
    Sapling(Option<[u8; 11]>),
}

impl Format for ZcashFormat {}

impl ZcashFormat {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix<N: ZcashNetwork>(&self) -> Vec<u8> {
        N::to_address_prefix(self)
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, AddressError> {
        if prefix.len() < 2 {
            return Err(AddressError::InvalidPrefixLength(prefix.len()));
        }

        match prefix[1] {
            0xB8 | 0x25 => Ok(ZcashFormat::P2PKH),
            0xBD | 0xBA => Ok(ZcashFormat::P2SH),
            0x9A | 0xB6 => Ok(ZcashFormat::Sprout),
            0x73 | 0x74 => Ok(ZcashFormat::Sapling(None)),
            _ => return Err(AddressError::InvalidPrefix(prefix.clone())),
        }
    }
}

impl fmt::Display for ZcashFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ZcashFormat::P2PKH => write!(f, "p2pkh"),
            ZcashFormat::P2SH => write!(f, "p2sh"),
            ZcashFormat::Sprout => write!(f, "sprout"),
            ZcashFormat::Sapling(_) => write!(f, "sapling"),
        }
    }
}

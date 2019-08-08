use crate::network::ZcashNetwork;
use crate::derivation_path::ZcashDerivationPath;

use wagyu_model::{AddressError, ChildIndex, FormatError};

use serde::Serialize;
use std::{boxed::Box, convert::TryFrom, fmt, str::FromStr};

/// Represents the format of a Zcash address
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize)]
pub enum ZcashFormat {
    /// Pay-to-Pubkey Hash, transparent address beginning with "t1" or "tm"
    P2PKH,
    /// Pay-to-Script Hash, transparent address beginning with "t3" or "t2"
    P2SH,
    /// Sprout shielded address beginning with "zc" or "zt"
    Sprout,
    /// Sapling shielded address beginning with "zs" or "ztestsapling"
    Sapling(Option<[u8; 11]>),

    /// Master key with no path
    Master,
    /// Sapling ZIP32 path with account and index
    ZIP32(u32, u32),
    /// Custom path with a specified format
    CustomPath(ZcashDerivationPath, Box<ZcashFormat>)
}

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

    /// Returns the corresponding derivation path from the child index
    pub fn from_child_index(path: &[ChildIndex], format: ZcashFormat) -> Result<Self, FormatError> {
        Ok(ZcashFormat::CustomPath(ZcashDerivationPath::try_from(path)?, Box::new(format)))
    }

    /// Returns the corresponding derivation path from the path
    pub fn from_path(path: &str, format: ZcashFormat) -> Result<Self, FormatError> {
        Ok(ZcashFormat::CustomPath(ZcashDerivationPath::from_str(path)?, Box::new(format)))
    }

    /// Returns the corresponding derivation path from the format
    pub fn to_derivation_path(&self) -> Result<ZcashDerivationPath, FormatError> {
        match self {
            ZcashFormat::Master => Ok(ZcashDerivationPath::from_str("m")?),
            ZcashFormat::ZIP32(account, index) => Ok(ZcashDerivationPath::zip32(*account, *index)?),
            ZcashFormat::CustomPath(derivation_path, _) => Ok(derivation_path.clone()),
            _ => Err(FormatError::UnsupportedDerivationPath(self.to_string())),
        }
    }
}

impl fmt::Display for ZcashFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ZcashFormat::P2PKH => write!(f, "p2pkh"),
            ZcashFormat::P2SH => write!(f, "p2sh"),
            ZcashFormat::Sprout => write!(f, "sprout"),
            ZcashFormat::Master => write!(f, "master"),
            ZcashFormat::Sapling(_) => write!(f, "sapling"),
            ZcashFormat::ZIP32(_, _) => write!(f, "sapling"),
            ZcashFormat::CustomPath(_, format) => write!(f, "{}", *format)
        }
    }
}
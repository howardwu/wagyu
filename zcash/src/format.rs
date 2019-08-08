use crate::network::ZcashNetwork;
use crate::derivation_path::ZcashDerivationPath;

use wagyu_model::{AddressError, ChildIndex, DerivationPathError};

use serde::Serialize;
use std::{boxed::Box, convert::TryFrom, fmt, str::FromStr};

/// Represents the format of a Zcash address
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize)]
pub enum Format {
    /// Pay-to-Pubkey Hash, transparent address beginning with "t1" or "tm"
    P2PKH,
    /// Pay-to-Script Hash, transparent address beginning with "t3" or "t2"
    P2SH,
    /// Sprout shielded address beginning with "zc" or "zt"
    Sprout,
    /// Sapling shielded address beginning with "zs" or "ztestsapling"
    Sapling(Option<[u8; 11]>),

    /// TODO fill out documentation
    Master,
    ZIP32(u32, u32),
    CustomPath(ZcashDerivationPath, Box<Format>)
}

impl Format {
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
            0xB8 | 0x25 => Ok(Format::P2PKH),
            0xBD | 0xBA => Ok(Format::P2SH),
            0x9A | 0xB6 => Ok(Format::Sprout),
            0x73 | 0x74 => Ok(Format::Sapling(None)),
            _ => return Err(AddressError::InvalidPrefix(prefix.clone())),
        }
    }

    /// Returns the corresponding derivation path from the child index
    pub fn from_child_index(path: &[ChildIndex], format: Format) -> Result<Self, DerivationPathError> {
        Ok(Format::CustomPath(ZcashDerivationPath::try_from(path)?, Box::new(format)))
    }

    /// Returns the corresponding derivation path from the path
    pub fn from_path(path: &str, format: Format) -> Result<Self, DerivationPathError> {
        Ok(Format::CustomPath(ZcashDerivationPath::from_str(path)?, Box::new(format)))
    }

    /// Returns the corresponding derivation path from the format
    pub fn to_derivation_path(&self) -> Result<ZcashDerivationPath, DerivationPathError> {
        match self {
            Format::Master => ZcashDerivationPath::from_str("m"),
            Format::ZIP32(account, index) => ZcashDerivationPath::zip32(*account, *index),
            Format::CustomPath(derivation_path, _) => Ok(derivation_path.clone()),
            _ => Err(DerivationPathError::InvalidDerivationPath("".to_string())), //TODO trait-ify Format and handle these errors gracefully
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Format::P2PKH => write!(f, "p2pkh"),
            Format::P2SH => write!(f, "p2sh"),
            Format::Sprout => write!(f, "sprout"),
            Format::Master => write!(f, "master"),
            Format::Sapling(_) => write!(f, "sapling"),
            Format::ZIP32(_, _) => write!(f, "sapling"),
            Format::CustomPath(_, format) => write!(f, "{}", *format)
        }
    }
}
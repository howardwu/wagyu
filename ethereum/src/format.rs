use crate::derivation_path::EthereumDerivationPath;

use wagyu_model::{ChildIndex, DerivationPathError};

use serde::Serialize;
use std::{fmt, str::FromStr};


/// Represents the format of a Ethereum derivation
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum Format {
    /// TODO fill out documentation
    Master,
    Ethereum(u32),
    Keepkey(u32),
    LedgerLegacy(u32),
    LedgerLive(u32),
    Trezor(u32),
    CustomPath(EthereumDerivationPath),
}

impl Format {

    /// Returns the corresponding derivation path from the child index
    pub fn from_child_index(path: &[ChildIndex]) -> Self {
        Format::CustomPath(EthereumDerivationPath::from(path))
    }

    /// Returns the corresponding derivation path from the path
    pub fn from_path(path: &str) -> Result<Self, DerivationPathError> {
        Ok(Format::CustomPath(EthereumDerivationPath::from_str(path)?))
    }

    /// Returns the corresponding derivation path from the format
    pub fn to_derivation_path(&self) -> Result<EthereumDerivationPath, DerivationPathError> {
        match self {
            Format::Master => EthereumDerivationPath::from_str("m"),
            Format::Ethereum(index) => EthereumDerivationPath::ethereum(*index),
            Format::Keepkey(index) => EthereumDerivationPath::keepkey(*index),
            Format::LedgerLegacy(index) => EthereumDerivationPath::ledger_legacy(*index),
            Format::LedgerLive(index) => EthereumDerivationPath::ledger_live(*index),
            Format::Trezor(index) => EthereumDerivationPath::trezor(*index),
            Format::CustomPath(derivation_path) => Ok(derivation_path.clone()),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Format::Master => write!(f, "master"),
            Format::Ethereum(_) => write!(f, "ethereum"),
            Format::Keepkey(_) => write!(f, "keepkey"),
            Format::LedgerLegacy(_) => write!(f, "ledger_legacy"),
            Format::LedgerLive(_) => write!(f, "ledger_live"),
            Format::Trezor(_) => write!(f, "trezor"),
            Format::CustomPath(path) => write!(f, "{}", path),
        }
    }
}
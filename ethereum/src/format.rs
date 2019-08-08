use crate::derivation_path::EthereumDerivationPath;

use wagyu_model::{ChildIndex, FormatError};

use serde::Serialize;
use std::{fmt, str::FromStr};


/// Represents the format of a Ethereum derivation
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum EthereumFormat {
    /// Master key with no path
    Master,
    /// Ethereum path with index
    Ethereum(u32),
    /// KeepKey path with index
    Keepkey(u32),
    /// Ledger Legacy path with index
    LedgerLegacy(u32),
    /// Ledger Live path with index
    LedgerLive(u32),
    /// Trezor path with index
    Trezor(u32),
    /// Custom path
    CustomPath(EthereumDerivationPath),
}

impl EthereumFormat {
    /// Returns the corresponding derivation path from the child index
    pub fn from_child_index(path: &[ChildIndex]) -> Self {
        Self::CustomPath(EthereumDerivationPath::from(path))
    }

    /// Returns the corresponding derivation path from the path
    pub fn from_path(path: &str) -> Result<Self, FormatError> {
        Ok(Self::CustomPath(EthereumDerivationPath::from_str(path)?))
    }

    /// Returns the corresponding derivation path from the format
    pub fn to_derivation_path(&self) -> Result<EthereumDerivationPath, FormatError> {
        match self {
            Self::Master => Ok(EthereumDerivationPath::from_str("m")?),
            Self::Ethereum(index) => Ok(EthereumDerivationPath::ethereum(*index)?),
            Self::Keepkey(index) => Ok(EthereumDerivationPath::keepkey(*index)?),
            Self::LedgerLegacy(index) => Ok(EthereumDerivationPath::ledger_legacy(*index)?),
            Self::LedgerLive(index) => Ok(EthereumDerivationPath::ledger_live(*index)?),
            Self::Trezor(index) => Ok(EthereumDerivationPath::trezor(*index)?),
            Self::CustomPath(derivation_path) => Ok(derivation_path.clone()),
        }
    }
}

impl fmt::Display for EthereumFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Master => write!(f, "master"),
            Self::Ethereum(_) => write!(f, "ethereum"),
            Self::Keepkey(_) => write!(f, "keepkey"),
            Self::LedgerLegacy(_) => write!(f, "ledger_legacy"),
            Self::LedgerLive(_) => write!(f, "ledger_live"),
            Self::Trezor(_) => write!(f, "trezor"),
            Self::CustomPath(path) => write!(f, "{}", path),
        }
    }
}
use wagu_model::derivation_path::{DerivationPath, DerivationPathError};

use std::fmt;
use std::str::FromStr;

/// Represents a child index for a derivation path
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChildIndex {
    // A non-hardened index: Normal(n) == n in path notation
    Normal(u32),
    // A hardened index: Hardened(n) == n + (1 << 31) == n' in path notation
    Hardened(u32),
}

impl ChildIndex {
    /// Returns [`Normal`] from an index, or errors if the index is not within [0, 2^31 - 1].
    pub fn from_normal(index: u32) -> Result<Self, DerivationPathError> {
        if index & (1 << 31) == 0 {
            Ok(ChildIndex::Normal(index))
        } else {
            Err(DerivationPathError::InvalidChildNumber(index))
        }
    }

    /// Returns [`Hardened`] from an index, or errors if the index is not within [0, 2^31 - 1].
    pub fn from_hardened(index: u32) -> Result<Self, DerivationPathError> {
        if index & (1 << 31) == 0 {
            Ok(ChildIndex::Hardened(index))
        } else {
            Err(DerivationPathError::InvalidChildNumber(index))
        }
    }
}

impl From<u32> for ChildIndex {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildIndex::Hardened(number ^ (1 << 31))
        } else {
            ChildIndex::Normal(number)
        }
    }
}

impl From<ChildIndex> for u32 {
    fn from(index: ChildIndex) -> Self {
        match index {
            ChildIndex::Normal(number) => number,
            ChildIndex::Hardened(number) => number | (1 << 31),
        }
    }
}

impl FromStr for ChildIndex {
    type Err = DerivationPathError;

    fn from_str(inp: &str) -> Result<Self, Self::Err> {
        Ok(match inp.chars().last().map_or(false, |l| l == '\'' || l == 'h') {
            true => Self::from_hardened(
                inp[0..inp.len() - 1].parse().map_err(|_| DerivationPathError::InvalidChildNumberFormat)?
            )?,
            false => Self::from_normal(
                inp.parse().map_err(|_| DerivationPathError::InvalidChildNumberFormat)?
            )?,
        })
    }
}

impl fmt::Display for ChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildIndex::Hardened(number) => write!(f, "{}'", number),
            ChildIndex::Normal(number) => write!(f, "{}", number),
        }
    }
}

/// Represents a Ethereum derivation path
#[derive(Clone, PartialEq, Eq)]
pub struct EthereumDerivationPath(pub(crate) Vec<ChildIndex>);

impl DerivationPath for EthereumDerivationPath {}

impl FromStr for EthereumDerivationPath {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut parts = path.split("/");

        if parts.next().unwrap() != "m" {
            return Err(DerivationPathError::InvalidDerivationPath(path.to_string()));
        }

        let path: Result<Vec<ChildIndex>, Self::Err> = parts.map(str::parse).collect();
        Ok(Self(path?))
    }
}

impl From<Vec<ChildIndex>> for EthereumDerivationPath {
    fn from(path: Vec<ChildIndex>) -> Self {
        Self(path)
    }
}

impl Into<Vec<ChildIndex>> for EthereumDerivationPath {
    fn into(self) -> Vec<ChildIndex> {
        self.0
    }
}

impl<'a> From<&'a [ChildIndex]> for EthereumDerivationPath {
    fn from(path: &'a [ChildIndex]) -> Self {
        Self(path.to_vec())
    }
}

impl fmt::Debug for EthereumDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl fmt::Display for EthereumDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for index in self.0.iter() {
            f.write_str("/")?;
            fmt::Display::fmt(index, f)?;
        }
        Ok(())
    }
}

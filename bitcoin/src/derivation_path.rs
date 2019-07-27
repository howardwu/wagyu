use wagu_model::derivation_path::DerivationPathError;

use std::str::FromStr;

/// Represents a child index for a derivation path
#[derive(Clone, Copy, Debug, PartialEq)]
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

/// Represents a Bitcoin derivation path
#[derive(Clone, Debug, PartialEq)]
pub struct BitcoinDerivationPath(Vec<ChildIndex>);

impl FromStr for BitcoinDerivationPath {
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

impl From<Vec<ChildIndex>> for BitcoinDerivationPath {
    fn from(path: Vec<ChildIndex>) -> Self {
        Self(path)
    }
}

impl Into<Vec<ChildIndex>> for BitcoinDerivationPath {
    fn into(self) -> Vec<ChildIndex> {
        self.0
    }
}

impl<'a> From<&'a [ChildIndex]> for BitcoinDerivationPath {
    fn from(path: &'a [ChildIndex]) -> Self {
        Self(path.to_vec())
    }
}

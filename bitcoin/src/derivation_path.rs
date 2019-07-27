use wagu_model::derivation_path::{ChildIndex, DerivationPath, DerivationPathError};

use std::fmt;
use std::str::FromStr;

/// Represents a Bitcoin derivation path
#[derive(Clone, PartialEq, Eq)]
pub struct BitcoinDerivationPath(pub(crate) Vec<ChildIndex>);

impl DerivationPath for BitcoinDerivationPath {}

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

impl fmt::Debug for BitcoinDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl fmt::Display for BitcoinDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for index in self.0.iter() {
            f.write_str("/")?;
            fmt::Display::fmt(index, f)?;
        }
        Ok(())
    }
}

use wagu_model::derivation_path::{ChildIndex, DerivationPath, DerivationPathError};

use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

/// Represents a Zcash derivation path
///
/// m_Sapling / purpose' / coin_type' / account' / address_index
/// https://github.com/zcash/zips/blob/master/zip-0032.rst
///
#[derive(Clone, PartialEq, Eq)]
pub struct ZcashDerivationPath(pub(crate) Vec<ChildIndex>);

impl DerivationPath for ZcashDerivationPath {}

impl FromStr for ZcashDerivationPath {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut parts = path.split("/");

        if parts.next().unwrap() != "m" {
            return Err(DerivationPathError::InvalidDerivationPath(path.to_string()))
        }

        let path: Result<Vec<ChildIndex>, Self::Err> = parts.map(str::parse).collect();
        Self::try_from(path?)
    }
}

impl TryFrom<Vec<ChildIndex>> for ZcashDerivationPath {
    type Error = DerivationPathError;

    fn try_from(path: Vec<ChildIndex>) -> Result<Self, Self::Error> {
        // The purpose' / coin_type' / account' must all be hardened
        // https://github.com/zcash/zips/blob/master/zip-0032.rst#sapling-key-path
        let primary = match path.len() > 3 { true => &path[0..3], false => &path };
        if !primary.iter().filter(|&&index| index.is_normal()).collect::<Vec<_>>().is_empty() {
            return Err(DerivationPathError::ExpectedHardenedPath)
        }

        Ok(Self(path))
    }
}

impl<'a> TryFrom<&'a [ChildIndex]> for ZcashDerivationPath {
    type Error = DerivationPathError;

    fn try_from(path: &'a [ChildIndex]) -> Result<Self, Self::Error> {
        Self::try_from(path.to_vec())
    }
}

impl fmt::Debug for ZcashDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl fmt::Display for ZcashDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for index in self.0.iter() {
            f.write_str("/")?;
            fmt::Display::fmt(index, f)?;
        }
        Ok(())
    }
}

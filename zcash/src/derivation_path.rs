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
pub struct ZcashDerivationPath(Vec<ChildIndex>);

impl DerivationPath for ZcashDerivationPath {}

impl FromStr for ZcashDerivationPath {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut parts = path.split("/");

        if parts.next().unwrap() != "m" {
            return Err(DerivationPathError::InvalidDerivationPath(path.to_string()));
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
        let primary = match path.len() > 3 {
            true => &path[0..3],
            false => &path,
        };
        if !primary
            .iter()
            .filter(|&&index| index.is_normal())
            .collect::<Vec<_>>()
            .is_empty()
        {
            return Err(DerivationPathError::ExpectedHardenedPath);
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

impl<'a> ::std::iter::IntoIterator for &'a ZcashDerivationPath {
    type Item = &'a ChildIndex;
    type IntoIter = ::std::slice::Iter<'a, ChildIndex>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
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

#[cfg(test)]
mod tests {
    use super::*;
    use wagu_model::derivation_path::{ChildIndex, DerivationPathError};

    use std::convert::TryInto;
    use std::str::FromStr;

    #[test]
    fn valid_path() {
        assert_eq!(ZcashDerivationPath::from_str("m"), Ok(vec![].try_into().unwrap()));
        assert_eq!(
            ZcashDerivationPath::from_str("m/0'"),
            Ok(vec![ChildIndex::from_hardened(0).unwrap()].try_into().unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0h/1'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap()
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0'/1h/2'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0h/1'/2h/3'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
                ChildIndex::from_hardened(3).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0'/1h/2'/3h/4'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
                ChildIndex::from_hardened(3).unwrap(),
                ChildIndex::from_hardened(4).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0h/1'/2h/3'/4"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
                ChildIndex::from_hardened(3).unwrap(),
                ChildIndex::from_normal(4).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0'/1'/2'/3'/4/5"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
                ChildIndex::from_hardened(3).unwrap(),
                ChildIndex::from_normal(4).unwrap(),
                ChildIndex::from_normal(5).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
    }

    #[test]
    fn invalid_path() {
        assert_eq!(
            ZcashDerivationPath::from_str("n"),
            Err(DerivationPathError::InvalidDerivationPath("n".into()))
        );
        assert_eq!(
            ZcashDerivationPath::from_str("n/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0".into()))
        );
        assert_eq!(
            ZcashDerivationPath::from_str("n/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0/0".into()))
        );

        assert_eq!(
            ZcashDerivationPath::from_str("1"),
            Err(DerivationPathError::InvalidDerivationPath("1".into()))
        );
        assert_eq!(
            ZcashDerivationPath::from_str("1/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0".into()))
        );
        assert_eq!(
            ZcashDerivationPath::from_str("1/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0/0".into()))
        );

        assert_eq!(
            ZcashDerivationPath::from_str("m/0x"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0x0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0x00"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );

        assert_eq!(
            ZcashDerivationPath::from_str("0/m"),
            Err(DerivationPathError::InvalidDerivationPath("0/m".into()))
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m//0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/2147483648"),
            Err(DerivationPathError::InvalidChildNumber(2147483648))
        );

        assert_eq!(
            ZcashDerivationPath::from_str("m/0"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0/1"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0'/1"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0/1'"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0/1/2"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0'/1/2"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0/1'/2"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0/1/2'"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0'/1'/2"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0'/1/2'"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
        assert_eq!(
            ZcashDerivationPath::from_str("m/0/1'/2'"),
            Err(DerivationPathError::ExpectedHardenedPath)
        );
    }
}

use crate::network::ZcashNetwork;
use wagyu_model::derivation_path::{ChildIndex, DerivationPath, DerivationPathError};

use std::{convert::TryFrom, fmt, marker::PhantomData, str::FromStr};

/// Represents a Zcash derivation path
#[derive(Clone, PartialEq, Eq)]
pub enum ZcashDerivationPath<N: ZcashNetwork> {
    /// Sapling ZIP32 - m/32'/{133', 1'}/{account}'
    /// https://github.com/zcash/zips/blob/master/zip-0032.rst#sapling-key-path
    /// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    ZIP32Sapling(ChildIndex),
    /// Sapling ZIP32 with Independent Spend Authorities - m/32'/{133', 1'}/{account}'/{index}
    /// https://github.com/zcash/zips/blob/master/zip-0032.rst#sapling-key-path
    /// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    ZIP32SaplingIndependent([ChildIndex; 2]),
    /// An unsupported derivation path that will error and
    /// is incompatible with Zcash structs in this library.
    /// https://github.com/zcash/zips/blob/master/zip-0032.rst#sapling-key-path
    Unsupported(Vec<ChildIndex>, PhantomData<N>),
}

impl<N: ZcashNetwork> DerivationPath for ZcashDerivationPath<N> {
    /// Returns a child index vector given the derivation path.
    fn to_vec(&self) -> Result<Vec<ChildIndex>, DerivationPathError> {
        match self {
            ZcashDerivationPath::ZIP32Sapling(index) => match index.is_hardened() {
                true => Ok(vec![N::HD_PURPOSE, N::HD_COIN_TYPE, *index]),
                false => Err(DerivationPathError::ExpectedZIP32Path),
            },
            ZcashDerivationPath::ZIP32SaplingIndependent(path) => match path[0].is_hardened() && path[1].is_normal() {
                true => Ok(vec![N::HD_PURPOSE, N::HD_COIN_TYPE, path[0], path[1]]),
                false => Err(DerivationPathError::ExpectedZIP32Path),
            },
            ZcashDerivationPath::Unsupported(_, _) => Err(DerivationPathError::ExpectedZIP32Path),
        }
    }

    /// Returns a derivation path given the child index vector.
    fn from_vec(path: &Vec<ChildIndex>) -> Result<Self, DerivationPathError> {
        if path.len() == 3 && path[0] == N::HD_PURPOSE && path[1] == N::HD_COIN_TYPE && path[2].is_hardened() {
            // Path length 3 - Sapling ZIP32
            Ok(ZcashDerivationPath::ZIP32Sapling(path[2]))
        } else if path.len() == 4
            && path[0] == N::HD_PURPOSE
            && path[1] == N::HD_COIN_TYPE
            && path[2].is_hardened()
            && path[3].is_normal()
        {
            // Path length 4 - Sapling ZIP32 with Independent Spend Authorities
            Ok(ZcashDerivationPath::ZIP32SaplingIndependent([path[2], path[3]]))
        } else {
            // Path length i - Unsupported derivation path
            Err(DerivationPathError::ExpectedZIP32Path)
        }
    }
}

impl<N: ZcashNetwork> FromStr for ZcashDerivationPath<N> {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut parts = path.split("/");

        if parts.next().unwrap() != "m" {
            return Err(DerivationPathError::InvalidDerivationPath(path.to_string()));
        }

        let path: Result<Vec<ChildIndex>, Self::Err> = parts.map(str::parse).collect();
        Self::from_vec(&path?)
    }
}

impl<N: ZcashNetwork> TryFrom<Vec<ChildIndex>> for ZcashDerivationPath<N> {
    type Error = DerivationPathError;

    fn try_from(path: Vec<ChildIndex>) -> Result<Self, Self::Error> {
        Self::from_vec(&path)
    }
}

impl<'a, N: ZcashNetwork> TryFrom<&'a [ChildIndex]> for ZcashDerivationPath<N> {
    type Error = DerivationPathError;

    fn try_from(path: &'a [ChildIndex]) -> Result<Self, Self::Error> {
        Self::from_vec(&path.to_vec())
    }
}

impl<N: ZcashNetwork> fmt::Debug for ZcashDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl<N: ZcashNetwork> fmt::Display for ZcashDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_vec() {
            Ok(path) => {
                f.write_str("m")?;
                for index in path.iter() {
                    f.write_str("/")?;
                    fmt::Display::fmt(index, f)?;
                }
                Ok(())
            }
            Err(_) => Err(fmt::Error),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::network::*;

    use std::convert::TryInto;

    #[test]
    fn valid_path() {
        use super::*;

        type N = Mainnet;

        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32'/133h/0'"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(0).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32'/133h/1'"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(1).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32'/133h/2'"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(2).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32'/133h/3'"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(3).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32'/133h/4'"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(4).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32h/133'/2h/0"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(0).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32h/133'/2h/1"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(1).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32h/133'/2h/2"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(2).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32h/133'/2h/3"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(3).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/32h/133'/2h/4"),
            Ok(vec![
                ChildIndex::hardened(32).unwrap(),
                ChildIndex::hardened(133).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(4).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
    }

    #[test]
    fn invalid_path() {
        use super::*;

        type N = Mainnet;

        assert_eq!(
            ZcashDerivationPath::<N>::from_str("n"),
            Err(DerivationPathError::InvalidDerivationPath("n".into()))
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("n/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0".into()))
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("n/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0/0".into()))
        );

        assert_eq!(
            ZcashDerivationPath::<N>::from_str("1"),
            Err(DerivationPathError::InvalidDerivationPath("1".into()))
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("1/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0".into()))
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("1/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0/0".into()))
        );

        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0x"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0x0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0x00"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );

        assert_eq!(
            ZcashDerivationPath::<N>::from_str("0/m"),
            Err(DerivationPathError::InvalidDerivationPath("0/m".into()))
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m//0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/2147483648"),
            Err(DerivationPathError::InvalidChildNumber(2147483648))
        );

        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0'"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0'/0'"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0/0"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0/1"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0'/1"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0/1'"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0/1/2"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0'/1/2"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0/1'/2"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0/1/2'"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0'/1'/2"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0'/1/2'"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
        assert_eq!(
            ZcashDerivationPath::<N>::from_str("m/0/1'/2'"),
            Err(DerivationPathError::ExpectedZIP32Path)
        );
    }
}

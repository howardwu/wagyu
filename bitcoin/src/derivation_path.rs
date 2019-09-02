use crate::network::BitcoinNetwork;
use wagyu_model::derivation_path::{ChildIndex, DerivationPath, DerivationPathError};

use std::{fmt, marker::PhantomData, str::FromStr};

/// Represents a Bitcoin derivation path
#[derive(Clone, PartialEq, Eq)]
pub enum BitcoinDerivationPath<N: BitcoinNetwork> {
    /// BIP32 - Pay-to-Pubkey Hash
    BIP32(Vec<ChildIndex>, PhantomData<N>),
    /// BIP44 - m/44'/{0', 1'}/{account}'/{change}/{index} - Pay-to-Pubkey Hash
    BIP44([ChildIndex; 3]),
    /// BIP49 - m/49'/{0', 1'}/{account}'/{change}/{index} - SegWit Pay-to-Witness-Public-Key Hash
    BIP49([ChildIndex; 3]),
}

impl<N: BitcoinNetwork> DerivationPath for BitcoinDerivationPath<N> {
    /// Returns a child index vector given the derivation path.
    fn to_vec(&self) -> Vec<ChildIndex> {
        match self {
            BitcoinDerivationPath::BIP32(path, _) => path.clone(),
            BitcoinDerivationPath::BIP44(path) => vec![
                ChildIndex::Hardened(44),
                N::HD_COIN_TYPE,
                path[0],
                path[1],
                path[2],
            ],
            BitcoinDerivationPath::BIP49(path) => vec![
                ChildIndex::Hardened(49),
                N::HD_COIN_TYPE,
                path[0],
                path[1],
                path[2],
            ],
        }
    }

    /// Returns a derivation path given the child index vector.
    fn from_vec(path: &Vec<ChildIndex>) -> Self {
        if path.len() == 5 {
            // Path length 5 - BIP44
            if path[0] == ChildIndex::Hardened(44)
                && path[1] == N::HD_COIN_TYPE
                && path[2].is_hardened()
                && path[3].is_normal()
                && path[4].is_normal() {
                return BitcoinDerivationPath::BIP44([path[2], path[3], path[4]])
            }
            // Path length 5 - BIP49
            if path[0] == ChildIndex::Hardened(49)
                && path[1] == N::HD_COIN_TYPE
                && path[2].is_hardened()
                && path[3].is_normal()
                && path[4].is_normal() {
                return BitcoinDerivationPath::BIP49([path[2], path[3], path[4]])
            }
            // Path length 5 - BIP32 (non-BIP44 & non-BIP49 compliant)
            return BitcoinDerivationPath::BIP32(path.to_vec(), PhantomData)

        } else {
            // Path length 0 - BIP32 root key
            // Path length i - BIP32
            BitcoinDerivationPath::BIP32(path.to_vec(), PhantomData)
        }
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinDerivationPath<N> {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut parts = path.split("/");

        if parts.next().unwrap() != "m" {
            return Err(DerivationPathError::InvalidDerivationPath(path.to_string()));
        }

        let path: Result<Vec<ChildIndex>, Self::Err> = parts.map(str::parse).collect();
        Ok(Self::from_vec(&path?))
    }
}

impl<N: BitcoinNetwork> From<Vec<ChildIndex>> for BitcoinDerivationPath<N> {
    fn from(path: Vec<ChildIndex>) -> Self {
        Self::from_vec(&path)
    }
}

impl<N: BitcoinNetwork> Into<Vec<ChildIndex>> for BitcoinDerivationPath<N> {
    fn into(self) -> Vec<ChildIndex> {
        self.to_vec()
    }
}

impl<'a, N: BitcoinNetwork> From<&'a [ChildIndex]> for BitcoinDerivationPath<N> {
    fn from(path: &'a [ChildIndex]) -> Self {
        Self::from_vec(&path.to_vec())
    }
}

impl<'a, N: BitcoinNetwork> ::std::iter::IntoIterator for &'a BitcoinDerivationPath<N> {
    type Item = ChildIndex;
    type IntoIter = ::std::vec::IntoIter<ChildIndex>;

    fn into_iter(self) -> Self::IntoIter {
        self.to_vec().into_iter()
    }
}

impl<N: BitcoinNetwork> fmt::Debug for BitcoinDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl<N: BitcoinNetwork> fmt::Display for BitcoinDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;

        for index in self.to_vec().iter() {
            f.write_str("/")?;
            fmt::Display::fmt(index, f)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;
    use wagyu_model::derivation_path::{ChildIndex, DerivationPathError};

    use std::str::FromStr;

    #[test]
    fn bip32() {
        use super::*;

        type N = Mainnet;

        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![], PhantomData), BitcoinDerivationPath::<N>::from_str("m").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Hardened(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0'").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Normal(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Hardened(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0/0'").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Hardened(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0/0/0'").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0/0/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Hardened(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0/0/0/0'").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0/0/0/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Hardened(0)], PhantomData), BitcoinDerivationPath::<N>::from_str("m/0/0/0/0/0'").unwrap());
    }

    #[test]
    fn bip44_mainnet() {
        use super::*;

        type N = Mainnet;

        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/44'/0'/0'/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/44'/0'/0'/0/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/44'/0'/0'/1/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/44'/0'/0'/1/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/44'/0'/1'/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/44'/0'/1'/0/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/44'/0'/1'/1/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/44'/0'/1'/1/1").unwrap());
    }

    #[test]
    fn bip44_testnet() {
        use super::*;

        type N = Testnet;

        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/44'/1'/0'/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/44'/1'/0'/0/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/44'/1'/0'/1/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/44'/1'/0'/1/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/44'/1'/1'/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/44'/1'/1'/0/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/44'/1'/1'/1/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/44'/1'/1'/1/1").unwrap());
    }

    #[test]
    fn bip49_mainnet() {
        use super::*;

        type N = Mainnet;

        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/49'/0'/0'/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/49'/0'/0'/0/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/49'/0'/0'/1/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/49'/0'/0'/1/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/49'/0'/1'/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/49'/0'/1'/0/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/49'/0'/1'/1/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/49'/0'/1'/1/1").unwrap());
    }

    #[test]
    fn bip49_testnet() {
        use super::*;

        type N = Testnet;

        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/49'/1'/0'/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/49'/1'/0'/0/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/49'/1'/0'/1/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/49'/1'/0'/1/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/49'/1'/1'/0/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/49'/1'/1'/0/1").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(0)]), BitcoinDerivationPath::<N>::from_str("m/49'/1'/1'/1/0").unwrap());
        assert_eq!(BitcoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(1)]), BitcoinDerivationPath::<N>::from_str("m/49'/1'/1'/1/1").unwrap());
    }

    #[test]
    fn valid_path() {
        use super::*;

        type N = Mainnet;

        assert_eq!(BitcoinDerivationPath::<N>::from_str("m"), Ok(vec![].into()));
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0"),
            Ok(vec![ChildIndex::from_normal(0).unwrap()].into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0/1"),
            Ok(vec![ChildIndex::from_normal(0).unwrap(), ChildIndex::from_normal(1).unwrap()].into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0/1/2"),
            Ok(vec![
                ChildIndex::from_normal(0).unwrap(),
                ChildIndex::from_normal(1).unwrap(),
                ChildIndex::from_normal(2).unwrap()
            ]
            .into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0/1/2/3"),
            Ok(vec![
                ChildIndex::from_normal(0).unwrap(),
                ChildIndex::from_normal(1).unwrap(),
                ChildIndex::from_normal(2).unwrap(),
                ChildIndex::from_normal(3).unwrap()
            ]
            .into())
        );

        assert_eq!(BitcoinDerivationPath::<N>::from_str("m"), Ok(vec![].into()));
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0'"),
            Ok(vec![ChildIndex::from_hardened(0).unwrap()].into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0'/1"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_normal(1).unwrap()
            ]
            .into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0'/1/2'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_normal(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0'/1/2'/3"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_normal(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
                ChildIndex::from_normal(3).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0'/1/2'/3/4'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_normal(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
                ChildIndex::from_normal(3).unwrap(),
                ChildIndex::from_hardened(4).unwrap(),
            ]
            .into())
        );

        assert_eq!(BitcoinDerivationPath::<N>::from_str("m"), Ok(vec![].into()));
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0h"),
            Ok(vec![ChildIndex::from_hardened(0).unwrap()].into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0h/1'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap()
            ]
            .into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0'/1h/2'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0h/1'/2h/3'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
                ChildIndex::from_hardened(3).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0'/1h/2'/3h/4'"),
            Ok(vec![
                ChildIndex::from_hardened(0).unwrap(),
                ChildIndex::from_hardened(1).unwrap(),
                ChildIndex::from_hardened(2).unwrap(),
                ChildIndex::from_hardened(3).unwrap(),
                ChildIndex::from_hardened(4).unwrap(),
            ]
            .into())
        );
    }

    #[test]
    fn invalid_path() {
        use super::*;

        type N = Mainnet;

        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("n"),
            Err(DerivationPathError::InvalidDerivationPath("n".into()))
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("n/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0".into()))
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("n/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0/0".into()))
        );

        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("1"),
            Err(DerivationPathError::InvalidDerivationPath("1".into()))
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("1/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0".into()))
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("1/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0/0".into()))
        );

        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0x"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0x0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/0x00"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );

        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("0/m"),
            Err(DerivationPathError::InvalidDerivationPath("0/m".into()))
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m//0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            BitcoinDerivationPath::<N>::from_str("m/2147483648"),
            Err(DerivationPathError::InvalidChildNumber(2147483648))
        );
    }
}

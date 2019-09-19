use crate::network::EthereumNetwork;
use wagyu_model::derivation_path::{ChildIndex, DerivationPath, DerivationPathError};

use std::convert::TryFrom;
use std::{fmt, marker::PhantomData, str::FromStr};

/// Represents a Ethereum derivation path
#[derive(Clone, PartialEq, Eq)]
pub enum EthereumDerivationPath<N: EthereumNetwork> {
    /// Ethereum Standard - m/44'/60'/0'/0/{index}
    Ethereum(ChildIndex),
    /// Exodus - m/44'/60'/0'/0/{index}
    Exodus(ChildIndex),
    /// Jaxx - m/44'/60'/0'/0/{index}
    Jaxx(ChildIndex),
    /// Metamask - m/44'/60'/0'/0/{index}
    MetaMask(ChildIndex),
    /// MyEtherWallet - m/44'/60'/0'/0/{index}
    MyEtherWallet(ChildIndex),
    /// Trezor - m/44'/60'/0'/0/{index}
    Trezor(ChildIndex),

    /// KeepKey - m/44'/60'/{index}'/0/0
    KeepKey(ChildIndex),
    /// Ledger Live - m/44'/60'/{index}'/0/0
    LedgerLive(ChildIndex),

    /// Electrum - m/44'/60'/0'/{index}
    Electrum(ChildIndex),
    /// imToken - m/44'/60'/0'/{index}
    ImToken(ChildIndex),
    /// imToken - m/44'/60'/0'/{index}
    LedgerLegacy(ChildIndex),

    /// Custom Ethereum derivation path
    Custom(Vec<ChildIndex>, PhantomData<N>),
}

impl<N: EthereumNetwork> DerivationPath for EthereumDerivationPath<N> {
    /// Returns a child index vector given the derivation path.
    fn to_vec(&self) -> Result<Vec<ChildIndex>, DerivationPathError> {
        match self {
            EthereumDerivationPath::Ethereum(index)
            | EthereumDerivationPath::Exodus(index)
            | EthereumDerivationPath::Jaxx(index)
            | EthereumDerivationPath::MetaMask(index)
            | EthereumDerivationPath::MyEtherWallet(index)
            | EthereumDerivationPath::Trezor(index) => match index.is_normal() {
                true => Ok(vec![
                    N::HD_PURPOSE,
                    N::HD_COIN_TYPE,
                    ChildIndex::Hardened(0),
                    ChildIndex::Normal(0),
                    *index,
                ]),
                false => Err(DerivationPathError::ExpectedBIP44Path),
            },

            EthereumDerivationPath::KeepKey(index) | EthereumDerivationPath::LedgerLive(index) => {
                match index.is_hardened() {
                    true => Ok(vec![
                        N::HD_PURPOSE,
                        N::HD_COIN_TYPE,
                        *index,
                        ChildIndex::Normal(0),
                        ChildIndex::Normal(0),
                    ]),
                    false => Err(DerivationPathError::ExpectedBIP44Path),
                }
            }

            EthereumDerivationPath::Electrum(index)
            | EthereumDerivationPath::ImToken(index)
            | EthereumDerivationPath::LedgerLegacy(index) => match index.is_normal() {
                true => Ok(vec![N::HD_PURPOSE, N::HD_COIN_TYPE, ChildIndex::Hardened(0), *index]),
                false => Err(DerivationPathError::ExpectedValidEthereumDerivationPath),
            },

            EthereumDerivationPath::Custom(path, _) => match path.len() < 256 {
                true => Ok(path.clone()),
                false => Err(DerivationPathError::ExpectedValidEthereumDerivationPath),
            },
        }
    }

    /// Returns a derivation path given the child index vector.
    fn from_vec(path: &Vec<ChildIndex>) -> Result<Self, DerivationPathError> {
        if path.len() == 4 {
            // Path length 4 - Electrum (default), imToken, LedgerLegacy
            if path[0] == N::HD_PURPOSE
                && path[1] == N::HD_COIN_TYPE
                && path[2] == ChildIndex::Hardened(0)
                && path[3].is_normal()
            {
                return Ok(EthereumDerivationPath::Electrum(path[3]));
            }
        }

        if path.len() == 5 {
            // Path length 5 - Ethereum (default), Exodus, Jaxx, MetaMask, MyEtherWallet, Trezor
            if path[0] == N::HD_PURPOSE
                && path[1] == N::HD_COIN_TYPE
                && path[2] == ChildIndex::Hardened(0)
                && path[3] == ChildIndex::Normal(0)
                && path[4].is_normal()
            {
                return Ok(EthereumDerivationPath::Ethereum(path[4]));
            }
            // Path length 5 - KeepKey, LedgerLive (default)
            if path[0] == ChildIndex::Hardened(49)
                && path[1] == N::HD_COIN_TYPE
                && path[2].is_hardened()
                && path[3] == ChildIndex::Normal(0)
                && path[4] == ChildIndex::Normal(0)
            {
                return Ok(EthereumDerivationPath::LedgerLive(path[2]));
            }
        }

        // Path length i - Custom Ethereum derivation path
        Ok(EthereumDerivationPath::Custom(path.to_vec(), PhantomData))
    }
}

impl<N: EthereumNetwork> FromStr for EthereumDerivationPath<N> {
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

impl<N: EthereumNetwork> TryFrom<Vec<ChildIndex>> for EthereumDerivationPath<N> {
    type Error = DerivationPathError;

    fn try_from(path: Vec<ChildIndex>) -> Result<Self, Self::Error> {
        Self::from_vec(&path)
    }
}

impl<'a, N: EthereumNetwork> TryFrom<&'a [ChildIndex]> for EthereumDerivationPath<N> {
    type Error = DerivationPathError;

    fn try_from(path: &'a [ChildIndex]) -> Result<Self, Self::Error> {
        Self::try_from(path.to_vec())
    }
}

impl<N: EthereumNetwork> fmt::Debug for EthereumDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl<N: EthereumNetwork> fmt::Display for EthereumDerivationPath<N> {
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
    use super::*;
    use crate::network::*;
    use wagyu_model::derivation_path::{ChildIndex, DerivationPathError};

    use std::convert::TryInto;
    use std::str::FromStr;

    #[test]
    fn valid_path() {
        type N = Mainnet;

        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m"),
            Ok(vec![].try_into().unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0"),
            Ok(vec![ChildIndex::normal(0).unwrap()].try_into().unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0/1"),
            Ok(vec![ChildIndex::normal(0).unwrap(), ChildIndex::normal(1).unwrap()]
                .try_into()
                .unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0/1/2"),
            Ok(vec![
                ChildIndex::normal(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::normal(2).unwrap()
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0/1/2/3"),
            Ok(vec![
                ChildIndex::normal(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::normal(2).unwrap(),
                ChildIndex::normal(3).unwrap()
            ]
            .try_into()
            .unwrap())
        );

        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m"),
            Ok(vec![].try_into().unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0'"),
            Ok(vec![ChildIndex::hardened(0).unwrap()].try_into().unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0'/1"),
            Ok(vec![ChildIndex::hardened(0).unwrap(), ChildIndex::normal(1).unwrap()]
                .try_into()
                .unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0'/1/2'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0'/1/2'/3"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(3).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0'/1/2'/3/4'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(3).unwrap(),
                ChildIndex::hardened(4).unwrap(),
            ]
            .try_into()
            .unwrap())
        );

        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m"),
            Ok(vec![].try_into().unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0h"),
            Ok(vec![ChildIndex::hardened(0).unwrap()].try_into().unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0h/1'"),
            Ok(vec![ChildIndex::hardened(0).unwrap(), ChildIndex::hardened(1).unwrap()]
                .try_into()
                .unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0'/1h/2'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::hardened(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0h/1'/2h/3'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::hardened(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::hardened(3).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0'/1h/2'/3h/4'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::hardened(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::hardened(3).unwrap(),
                ChildIndex::hardened(4).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
    }

    #[test]
    fn invalid_path() {
        type N = Mainnet;

        assert_eq!(
            EthereumDerivationPath::<N>::from_str("n"),
            Err(DerivationPathError::InvalidDerivationPath("n".try_into().unwrap()))
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("n/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0".try_into().unwrap()))
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("n/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0/0".try_into().unwrap()))
        );

        assert_eq!(
            EthereumDerivationPath::<N>::from_str("1"),
            Err(DerivationPathError::InvalidDerivationPath("1".try_into().unwrap()))
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("1/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0".try_into().unwrap()))
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("1/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0/0".try_into().unwrap()))
        );

        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0x"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0x0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/0x00"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );

        assert_eq!(
            EthereumDerivationPath::<N>::from_str("0/m"),
            Err(DerivationPathError::InvalidDerivationPath("0/m".try_into().unwrap()))
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m//0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            EthereumDerivationPath::<N>::from_str("m/2147483648"),
            Err(DerivationPathError::InvalidChildNumber(2147483648))
        );
    }
}

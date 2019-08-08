use crate::derivation_path::BitcoinDerivationPath;
use crate::network::BitcoinNetwork;

use wagyu_model::FormatError;

use serde::Serialize;
use std::{boxed::Box, fmt, str::FromStr};

/// Represents the format of a Bitcoin derivation path and/or address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum BitcoinFormat {
    /// Pay-to-Pubkey Hash, e.g. 1NoZQSmjYHUZMbqLerwmT4xfe8A6mAo8TT
    P2PKH,
    /// SegWit Pay-to-Witness-Public-Key Hash, e.g. 34AgLJhwXrvmkZS1o5TrcdeevMt22Nar53
    P2SH_P2WPKH,
    /// Bech32, e.g. bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx
    Bech32,

    /// Master key with no path
    Master,
    /// BIP32 path with index - Pay-to-Pubkey Hash
    BIP32(u32),
    /// BIP44 path with account, chain, and index - Pay-to-Pubkey Hash
    BIP44(u32, u32, u32),
    /// BIP49 path with account, chain, and index - SegWit Pay-to-Witness-Public-Key Hash
    BIP49(u32, u32, u32),
    /// Custom path with a specified format
    CustomPath(BitcoinDerivationPath, Box<Self>),
}

impl BitcoinFormat {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix<N: BitcoinNetwork>(&self) -> Vec<u8> {
        N::to_address_prefix(self)
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: &[u8]) -> Result<Self, FormatError> {
        if prefix.len() < 2 {
            return Err(FormatError::InvalidPrefix(prefix.to_vec()));
        }
        match (prefix[0], prefix[1]) {
            (0x00, _) | (0x6F, _) => Ok(Self::P2PKH),
            (0x05, _) | (0xC4, _) => Ok(Self::P2SH_P2WPKH),
            (0x62, 0x63) | (0x74, 0x62) => Ok(Self::Bech32),
            _ => return Err(FormatError::InvalidPrefix(prefix.to_vec())),
        }
    }

    /// Returns the network of the given extended private key version bytes.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    pub fn from_extended_private_key_version_bytes(prefix: &[u8]) -> Result<Self, FormatError> {
        match prefix[0..4] {
            [0x04, 0x88, 0xAD, 0xE4] | [0x04, 0x35, 0x83, 0x94] => Ok(Self::P2PKH),
            [0x04, 0x9D, 0x78, 0x78] | [0x04, 0x4A, 0x4E, 0x28] => Ok(Self::P2SH_P2WPKH),
            _ => Err(FormatError::InvalidVersionBytes(prefix.to_vec())),
        }
    }

    /// Returns the network of the given extended public key version bytes.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    pub fn from_extended_public_key_version_bytes(prefix: &[u8]) -> Result<Self, FormatError> {
        match prefix[0..4] {
            [0x04, 0x88, 0xB2, 0x1E] | [0x04, 0x35, 0x87, 0xCF] => Ok(Self::P2PKH),
            [0x04, 0x9D, 0x7C, 0xB2] | [0x04, 0x4A, 0x52, 0x62] => Ok(Self::P2SH_P2WPKH),
            _ => Err(FormatError::InvalidVersionBytes(prefix.to_vec())),
        }
    }

    /// Returns the corresponding derivation path from the path
    pub fn from_path(path: &str, format: Self) -> Result<Self, FormatError> {
        Ok(Self::CustomPath(BitcoinDerivationPath::from_str(path)?, Box::new(format)))
    }

    /// Returns the corresponding derivation path from the format
    pub fn to_derivation_path(&self) -> Result<BitcoinDerivationPath, FormatError> {
        match self {
            Self::Master => Ok(BitcoinDerivationPath::from_str("m")?),
            Self::BIP32(index) => Ok(BitcoinDerivationPath::from_str(&format!("m/0'/0'/{}'", index))?),
            Self::BIP44(account, chain, index) => Ok(BitcoinDerivationPath::from_str(&format!("m/44'/0'/{}'/{}/{}'", account, chain, index))?),
            Self::BIP49(account, chain, index) => Ok(BitcoinDerivationPath::from_str(&format!("m/49'/0'/{}'/{}/{}'", account, chain, index))?),
            Self::CustomPath(derivation_path, _) => Ok(derivation_path.clone()),
            _ => Err(FormatError::UnsupportedDerivationPath(self.to_string())),
        }
    }
}

impl fmt::Display for BitcoinFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::P2PKH => write!(f, "p2pkh"),
            Self::P2SH_P2WPKH => write!(f, "p2sh_p2wpkh"),
            Self::Bech32 => write!(f, "bech32"),
            Self::Master => write!(f, "master"),
            Self::BIP32(_) => write!(f, "p2pkh"),
            Self::BIP44(_, _, _) => write!(f, "p2pkh"),
            Self::BIP49(_, _, _) => write!(f, "p2sh_p2wpkh"),
            Self::CustomPath(format, _) => write!(f, "{}", *format)
        }
    }
}
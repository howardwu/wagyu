use crate::network::TronNetwork;
use wagyu_model::{AddressError, ExtendedPrivateKeyError, ExtendedPublicKeyError, Format};
use wagyu_model::no_std::*;

use core::fmt;
use serde::Serialize;

/// Represents the format of a Tron address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum TronFormat {
    Tron,
    /// Pay-to-Pubkey Hash, e.g. 1NoZQSmjYHUZMbqLerwmT4xfe8A6mAo8TT
    P2PKH,
    /// Pay-to-Witness-Script Hash, e.g. 347N1Thc213QqfYCz3PZkjoJpNv5b14kBd
    P2WSH,
    /// SegWit Pay-to-Witness-Public-Key Hash, e.g. 34AgLJhwXrvmkZS1o5TrcdeevMt22Nar53
    P2SH_P2WPKH,
    /// Bech32, e.g. bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx
    Bech32,
}

impl Format for TronFormat {}

impl TronFormat {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix<N: TronNetwork>(&self) -> Vec<u8> {
        N::to_address_prefix(self)
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        if prefix.len() < 2 {
            return Err(AddressError::InvalidPrefix(prefix.to_vec()));
        }
        match (prefix[0], prefix[1]) {
            (0x41, _) => Ok(TronFormat::Tron),
            (0x00, _) | (0x6F, _) => Ok(TronFormat::P2PKH),
            (0x05, _) | (0xC4, _) => Ok(TronFormat::P2SH_P2WPKH),
            (0x62, 0x63) | (0x74, 0x62) => Ok(TronFormat::Bech32),
            _ => return Err(AddressError::InvalidPrefix(prefix.to_vec())),
        }
    }

    /// Returns the network of the given extended private key version bytes.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    pub fn from_extended_private_key_version_bytes(prefix: &[u8]) -> Result<Self, ExtendedPrivateKeyError> {
        match prefix[0..4] {
            [0x04, 0x88, 0xAD, 0xE4] | [0x04, 0x35, 0x83, 0x94] => Ok(TronFormat::P2PKH),
            [0x04, 0x9D, 0x78, 0x78] | [0x04, 0x4A, 0x4E, 0x28] => Ok(TronFormat::P2SH_P2WPKH),
            _ => Err(ExtendedPrivateKeyError::InvalidVersionBytes(prefix.to_vec())),
        }
    }

    /// Returns the network of the given extended public key version bytes.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    pub fn from_extended_public_key_version_bytes(prefix: &[u8]) -> Result<Self, ExtendedPublicKeyError> {
        match prefix[0..4] {
            [0x04, 0x88, 0xB2, 0x1E] | [0x04, 0x35, 0x87, 0xCF] => Ok(TronFormat::P2PKH),
            [0x04, 0x9D, 0x7C, 0xB2] | [0x04, 0x4A, 0x52, 0x62] => Ok(TronFormat::P2SH_P2WPKH),
            _ => Err(ExtendedPublicKeyError::InvalidVersionBytes(prefix.to_vec())),
        }
    }
}

impl fmt::Display for TronFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TronFormat::Tron => write!(f, "tron"),
            TronFormat::P2PKH => write!(f, "p2pkh"),
            TronFormat::P2WSH => write!(f, "p2wsh"),
            TronFormat::P2SH_P2WPKH => write!(f, "p2sh_p2wpkh"),
            TronFormat::Bech32 => write!(f, "bech32"),
        }
    }
}

use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use crate::no_std::*;
use wagyu_model::{
    AddressError, ChildIndex, ExtendedPrivateKeyError, ExtendedPublicKeyError, Network, NetworkError, PrivateKeyError,
};

use core::{fmt, str::FromStr};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Mainnet;

impl Network for Mainnet {
    const NAME: &'static str = "mainnet";
}

impl BitcoinNetwork for Mainnet {
    const HD_COIN_TYPE: ChildIndex = ChildIndex::Hardened(0);

    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &BitcoinFormat) -> Vec<u8> {
        match format {
            BitcoinFormat::P2PKH => vec![0x00],
            BitcoinFormat::P2WSH => vec![0x05],
            BitcoinFormat::P2SH_P2WPKH => vec![0x05],
            BitcoinFormat::Bech32 => vec![0x62, 0x63],
        }
    }

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError> {
        match (prefix[0], prefix[1]) {
            (0x00, _) | (0x05, _) | (0x62, 0x63) => Ok(Self),
            _ => Err(AddressError::InvalidPrefix(prefix.to_owned())),
        }
    }

    /// Returns the wif prefix of the given network.
    fn to_private_key_prefix() -> u8 {
        0x80
    }

    /// Returns the network of the given wif prefix.
    fn from_private_key_prefix(prefix: u8) -> Result<Self, PrivateKeyError> {
        match prefix {
            0x80 => Ok(Self),
            _ => Err(PrivateKeyError::InvalidPrefix(vec![prefix])),
        }
    }

    /// Returns the extended private key version bytes of the given network.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    fn to_extended_private_key_version_bytes(format: &BitcoinFormat) -> Result<Vec<u8>, ExtendedPrivateKeyError> {
        match format {
            BitcoinFormat::P2PKH => Ok(vec![0x04, 0x88, 0xAD, 0xE4]), // xprv
            BitcoinFormat::P2SH_P2WPKH => Ok(vec![0x04, 0x9D, 0x78, 0x78]), // yprv
            _ => Err(ExtendedPrivateKeyError::UnsupportedFormat(format.to_string())),
        }
    }

    /// Returns the network of the given extended private key version bytes.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    fn from_extended_private_key_version_bytes(prefix: &[u8]) -> Result<Self, ExtendedPrivateKeyError> {
        match prefix[0..4] {
            [0x04, 0x88, 0xAD, 0xE4] | [0x04, 0x9D, 0x78, 0x78] => Ok(Self),
            _ => Err(ExtendedPrivateKeyError::InvalidVersionBytes(prefix.to_vec())),
        }
    }

    /// Returns the extended public key version bytes of the given network.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    fn to_extended_public_key_version_bytes(format: &BitcoinFormat) -> Result<Vec<u8>, ExtendedPublicKeyError> {
        match format {
            BitcoinFormat::P2PKH => Ok(vec![0x04, 0x88, 0xB2, 0x1E]), // xpub
            BitcoinFormat::P2SH_P2WPKH => Ok(vec![0x04, 0x9D, 0x7C, 0xB2]), // ypub
            _ => Err(ExtendedPublicKeyError::UnsupportedFormat(format.to_string())),
        }
    }

    /// Returns the network of the given extended public key version bytes.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    fn from_extended_public_key_version_bytes(prefix: &[u8]) -> Result<Self, ExtendedPublicKeyError> {
        match prefix[0..4] {
            [0x04, 0x88, 0xB2, 0x1E] | [0x04, 0x9D, 0x7C, 0xB2] => Ok(Self),
            _ => Err(ExtendedPublicKeyError::InvalidVersionBytes(prefix.to_vec())),
        }
    }
}

impl FromStr for Mainnet {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Mainnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

use model::{Address, PrivateKey, to_hex_string};
use private_key::EthereumPrivateKey;
use public_key::EthereumPublicKey;

use serde::Serialize;
use std::fmt;
use tiny_keccak::keccak256;

/// Represents the format of a Ethereum address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Standard hex representation of an Ethereum address e.g "0xE9651749aA149fd5aa53c7352d3041284aa64986"
    Standard,
}

/// Represents an Ethereum address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash)]
pub struct EthereumAddress {
    pub address: String,
}

impl Address for EthereumAddress {
    type Format = Format;
    type PrivateKey = EthereumPrivateKey;
    type PublicKey = EthereumPublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: Option<Self::Format>) -> Self {
        Self::from_public_key(&private_key.to_public_key(), format)
    }

    /// Returns the address corresponding to the given public key.
    fn from_public_key(public_key: &Self::PublicKey, _: Option<Self::Format>) -> Self {
        Self::checksum_address(public_key)
    }
}

impl EthereumAddress {

    /// Returns the checksum address given a public key.
    /// Adheres to EIP-55 (https://eips.ethereum.org/EIPS/eip-55).
    pub fn checksum_address(public_key: &EthereumPublicKey) -> Self {
        let hash = keccak256(&public_key.public_key.serialize_uncompressed()[1..]);
        let address = to_hex_string(&hash[12..]).to_lowercase();

        let hash = to_hex_string(&keccak256(address.as_bytes()));
        let mut checksum_address = "0x".to_string();
        for c in 0..40 {
            let ch = match &hash[c..=c] {
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => address[c..=c].to_lowercase(),
                _ => address[c..=c].to_uppercase(),
            };
            checksum_address.push_str(&ch);
        }
        EthereumAddress { address: checksum_address }
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}
use utils::{to_checksum_address, to_hex_string};

use model::address::Address;
use model::private_key::PrivateKey;
use network::Network;
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
    //    /// <THAT WEIRD REPRESENTATION> representation of an Ethereum address e.g "INSERT EXAMPLE HERE"
    //    Weird, Commented out because i can't remember what the name of it was
}

/// Represents an Ethereum Address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash)]
pub struct EthereumAddress {
    pub address: String,
}

impl Address for EthereumAddress {
    type Format = (Format, Network);
    type PrivateKey = EthereumPrivateKey;
    type PublicKey = EthereumPublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: Option<Self::Format>) -> Self {
        let public_key = private_key.to_public_key();
        Self::from_public_key(&public_key, format)
    }

    /// Returns the address corresponding to the given public key.
    fn from_public_key(public_key: &Self::PublicKey, _format: Option<Self::Format>) -> Self {
        let public_key = public_key.public_key.serialize_uncompressed();
        let hash = keccak256(&public_key[1..]);

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..]);

        let address = to_checksum_address(&to_hex_string(&address_bytes).to_lowercase());

        EthereumAddress { address }
    }
}

impl EthereumAddress {
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

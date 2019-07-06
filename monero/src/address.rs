use model::{Address, PrivateKey};
use network::{Network, MAINNET_ADDRESS_BYTE, TESTNET_ADDRESS_BYTE};
use private_key::MoneroPrivateKey;
use public_key::MoneroPublicKey;

use base58::ToBase58;
use serde::Serialize;
use std::fmt;
use std::marker::PhantomData;
use tiny_keccak::keccak256;

/// Represents the format of a Monero address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Standard address format
    Standard
}

/// Represents a Monero address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroAddress {
    /// The Monero address
    pub address: String,

    /// The Network on which this address is usable
    pub network:Network,
}

impl Address for MoneroAddress {
    type Format = PhantomData<u8>;
    type Network = Network;
    type PrivateKey = MoneroPrivateKey;
    type PublicKey = MoneroPublicKey;

    /// Returns the address corresponding to the given Monero private key.
    fn from_private_key(private_key: &Self::PrivateKey, _: &Self::Format) -> Self {
        Self::from_public_key(&private_key.to_public_key(), &PhantomData, &private_key.network)
    }

    /// Returns the address corresponding to the given Bitcoin public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        _: &Self::Format,
        network: &Self::Network,
    ) -> Self {
        let address =
            MoneroAddress::generate_address(&network, &public_key.public_spend_key, &public_key.public_view_key);
        Self { address, network: *network }
    }
}

impl MoneroAddress {
    /// Generate Monero address
    pub fn generate_address(
        network: &Network,
        spend_key: &[u8; 32],
        view_key: &[u8; 32],
    ) -> String {
        let network_byte = match network {
            Network::Mainnet => MAINNET_ADDRESS_BYTE,
            Network::Testnet => TESTNET_ADDRESS_BYTE,
        };

        let mut bytes = vec![network_byte];
        bytes.extend(spend_key.iter().cloned());
        bytes.extend(view_key.iter().cloned());

        let hash = &keccak256(bytes.as_slice())[..4];
        bytes.extend(hash.iter().cloned());

        // Convert to base58 in 8 byte chunks
        let mut base58 = String::new();
        for chunk in bytes.as_slice().chunks(8) {
            let mut part = chunk.to_base58();
            let exp_len = match chunk.len() {
                8 => 11,
                6 => 9,
                5 => 7,
                _ => panic!("Invalid chunk length: {}", chunk.len()),
            };
            let missing = exp_len - part.len();
            if missing > 0 {
                part.insert_str(0, &"11111111111"[..missing]);
            }
            base58.push_str(&part);
        }

        base58
    }
}

impl fmt::Display for MoneroAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

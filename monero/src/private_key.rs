use crate::address::MoneroAddress;
use model::{Address, PrivateKey, PublicKey};
use crate::network::Network;
use crate::public_key::MoneroPublicKey;

use curve25519_dalek::{scalar::Scalar};
use rand::Rng;
use rand::rngs::OsRng;
use std::{fmt, fmt::Display};
use std::marker::PhantomData;
use std::str::FromStr;
use tiny_keccak::keccak256;

/// Represents a Monero private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MoneroPrivateKey {
    /// The private spending key
    pub private_spend_key: [u8; 32],
    /// The private viewing key
    pub private_view_key: [u8; 32],
    /// The network of the private key
    pub network: Network,
}

impl PrivateKey for MoneroPrivateKey {
    type Address = MoneroAddress;
    type Format = PhantomData<u8>;
    type Network = Network;
    type PublicKey = MoneroPublicKey;

    /// Returns a randomly-generated Monero private key.
    fn new(network: &Self::Network) -> Self {
        let mut csprng: OsRng = OsRng::new().unwrap();
        Self::from_seed(csprng.gen(), network)
    }

    /// Returns the public key of the corresponding Monero private key.
    fn to_public_key(&self) -> Self::PublicKey {
        MoneroPublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Monero private key.
    fn to_address(&self, _: &Self::Format) -> Self::Address {
        MoneroAddress::from_private_key(self, &PhantomData)
    }
}

impl MoneroPrivateKey {
    /// Returns a private key given seed bytes.
    pub fn from_seed(seed: [u8; 32], network: &Network) -> Self {
        let private_spend_key = Scalar::from_bytes_mod_order(seed).to_bytes();
        Self {
            private_spend_key,
            private_view_key: Scalar::from_bytes_mod_order(keccak256(&private_spend_key)).to_bytes(),
            network: *network
        }
    }

    /// Returns a private key given a private spend key.
    pub fn from_private_spend_key(private_spend_key: &[u8; 32], network: &Network) -> Self {
        Self {
            private_spend_key: *private_spend_key,
            private_view_key: Scalar::from_bytes_mod_order(keccak256(private_spend_key)).to_bytes(),
            network: *network
        }
    }
}

impl Default for MoneroPrivateKey {
    /// Returns a randomly-generated mainnet Monero private key.
    fn default() -> Self {
        Self::new(&Network::Mainnet)
    }
}

impl FromStr for MoneroPrivateKey {
    type Err = &'static str;
    // TODO (howardwu): Add parsing of mainnet or testnet as an option.
    fn from_str(s: &str) -> Result<Self, &'static str> {
        let seed = hex::decode(s).expect("error decoding string");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(seed.as_slice());
        Ok(Self::from_seed(bytes, &Network::Mainnet))
    }
}

impl Display for MoneroPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(")?;
        for byte in &self.private_spend_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ", ")?;
        for byte in &self.private_view_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}
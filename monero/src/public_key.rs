use address::MoneroAddress;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use model::{Address, PublicKey};
use network::Network;
use private_key::MoneroPrivateKey;

use std::{fmt, fmt::Display};
use tiny_keccak::keccak256;
use serde::export::PhantomData;

/// Represents a Monero public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroPublicKey {

    /// The public spending key
    pub public_spend_key: [u8; 32],
    
    /// The public viewing key
    pub public_view_key: [u8; 32],

}

impl PublicKey for MoneroPublicKey {
    type Address = MoneroAddress;
    type Format = PhantomData<u8>;
    type Network = Network;
    type PrivateKey = MoneroPrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        let hash = keccak256(&private_key.private_spend_key);
        let public_spend_key = MoneroPublicKey::scalar_mul_by_b_compressed(&private_key.private_spend_key);
        let public_view_key = MoneroPublicKey::scalar_mul_by_b_compressed(&hash);

        Self {public_spend_key, public_view_key}
    }

    /// Returns the address of the corresponding private key.
    fn to_address(
        &self,
        _: &Self::Format,
        network: &Self::Network
    ) -> Self::Address {
        MoneroAddress::from_public_key(self, &PhantomData, network)
    }
}

impl MoneroPublicKey {
    pub fn scalar_mul_by_b_compressed(bits: &[u8; 32]) -> [u8; 32] {
        let point = &Scalar::from_bits(*bits) * &ED25519_BASEPOINT_TABLE;
        let compressed = *point.compress().as_bytes();
        compressed
    }
}

impl Display for MoneroPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(")?;
        for byte in &self.public_spend_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ", ")?;
        for byte in &self.public_view_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

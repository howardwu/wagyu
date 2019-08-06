use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use std::{fmt, fmt::Display, marker::PhantomData, str::FromStr};
use tiny_keccak::keccak256;
use crate::MoneroPrivateKey;


/// Represents a one time key
pub struct OneTimeKey {
    /// Destination key from receiver's public keys and sender randomness
    destination_key: [u8; 32],
    /// Transaction identifier from sender randomness and base point
    transaction_public_key: Scalar
}

impl<N: MoneroNetwork> OneTimeKey {
    /// Returns one time public key given recipient public keys, randomness, and output index
    pub fn new(public: &MoneroPublicKey<N>, rand: [u8; 32], index: u32) -> OneTimeKey {
        //P = H_s(rA || n)G + B
        let r = Scalar::from_bits(rand);
        let A = Scalar::from_bits(public.to_public_view_key());
        let B = Scalar::from_bits(public.to_public_spend_key());

        let rA = r * A;
        let mut concat = Vec::<u8>::from(rA);
        concat.extend(index);

        let hash = Scalar::from_bytes_mod_order(keccak256(&concat));
        let base = hash * ED25519_BASEPOINT_TABLE;
        let P = base + B;

        Self {
            destination_key: P,
            transaction_public_key: r * ED25519_BASEPOINT_TABLE
        }
    }

    /// Verifies that a one time public key can be generated from recipient private keys
    pub fn verify(&self, private: &MoneroPrivateKey<N>, index: u32) -> bool {
        let expected = self.to_public(private, index);

        self.to_destination_key() == expected
    }

    /// Returns one time public key given recipient private keys
    pub fn to_public(&self, private: &MoneroPrivateKey<N>, index: u32) -> [u8; 32] {
        //P = (H_s(aR || n) + b) * G
        let one_time_private_key = self.to_private(private, index);
        let x = Scalar::from_bits(one_time_private_key);
        let P = x * ED25519_BASEPOINT_TABLE;

        P
    }

    /// Returns one time private key given recipient private keys
    pub fn to_private(&self, private: &MoneroPrivateKey<N>, index: u32) -> [u8; 32] {
        //x = H_s(aR || n) + b
        let R = self.to_transaction_public_key();
        let a = Scalar::from_bits(private.to_private_view_key());
        let b = Scalar::from_bits(private.to_private_spend_key());

        let aR: Scalar = a * R;
        let mut concat = Vec::<u8>::from(rA);
        concat.extend(index);

        let hash = Scalar::from_bytes_mod_order(keccak256(&concat));
        let x = hash + b;

        x
    }

    pub fn to_destination_key(&self) -> [u8; 32] {
        self.destination_key
    }

    pub fn to_transaction_public_key(&self) -> Scalar {
        self.transaction_public_key
    }
}
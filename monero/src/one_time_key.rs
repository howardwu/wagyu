use crate::network::MoneroNetwork;
use crate::address::{Format};
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use std::{marker::PhantomData};
use tiny_keccak::keccak256;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};


/// Represents a one time key
pub struct OneTimeKey<N: MoneroNetwork> {
    /// Destination key from receiver's public keys and sender randomness
    destination_key: [u8; 32],
    /// Transaction identifier from sender randomness and base point
    transaction_public_key: [u8; 32],
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: MoneroNetwork> OneTimeKey<N> {
    /// Returns one time key given recipient public keys, randomness, and output index
    pub fn new(public: &MoneroPublicKey<N>, rand: [u8; 32], index: u32) -> OneTimeKey<N> {
        //P = H_s(rA || n)G + B
        let r = Scalar::from_bits(rand);
        let A = CompressedEdwardsY(public.to_public_view_key()).decompress().unwrap(); //TODO: remove unwraps
        let B = CompressedEdwardsY(public.to_public_spend_key()).decompress().unwrap();

        let rA: EdwardsPoint = r * A;
        let mut concat : Vec<u8> = rA.compress().to_bytes().to_vec();
        concat.extend(&index.to_le_bytes());

        let H_s = Scalar::from_bytes_mod_order(keccak256(&concat));
        let base: EdwardsPoint = &H_s * &ED25519_BASEPOINT_TABLE;
        let P = &base + &B;
        let tx = &r * &ED25519_BASEPOINT_TABLE;

        Self {
            destination_key: P.compress().to_bytes(),
            transaction_public_key: tx.compress().to_bytes(),
            _network: PhantomData,
        }
    }

    /// Returns one time private key given recipient private keys
    pub fn to_private(&self, private: &MoneroPrivateKey<N>, index: u32) -> [u8; 32] {
        //x = H_s(aR || n) + b
        let R = CompressedEdwardsY(self.to_transaction_public_key()).decompress().unwrap();
        let a = Scalar::from_bits(private.to_private_view_key());
        let b = Scalar::from_bits(private.to_private_spend_key());

        let aR: EdwardsPoint = a * R;
        let mut concat: Vec<u8> = aR.compress().to_bytes().to_vec();
        concat.extend(&index.to_le_bytes());

        let H_s = Scalar::from_bytes_mod_order(keccak256(&concat));
        let x: Scalar = H_s + b;

        x.to_bytes()
    }

    /// Returns one time public key given recipient private keys
    pub fn to_public(&self, private: &MoneroPrivateKey<N>, index: u32) -> [u8; 32] {
        //P = (H_s(aR || n) + b) * G
        let one_time_private_key = self.to_private(private, index);
        let P = &Scalar::from_bits(one_time_private_key) * &ED25519_BASEPOINT_TABLE;

        P.compress().to_bytes()
    }

    /// Verifies that a one time public key can be generated from recipient private keys
    pub fn verify(&self, private: &MoneroPrivateKey<N>, index: u32) -> bool {
        let expected = self.to_public(private, index);

        self.to_destination_key() == expected
    }

    pub fn to_destination_key(&self) -> [u8; 32] {
        self.destination_key
    }

    pub fn to_transaction_public_key(&self) -> [u8; 32] {
        self.transaction_public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mainnet;
    use hex;

    type N = Mainnet;

    const FORMAT: &Format = &Format::Standard;

    // (seed, (private_spend_key, private_view_key), (public_spend_key, public_view_key), address)
    const KEYPAIRS: [(&str, (&str, &str), (&str, &str), &str); 1] = [
        (
            "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                "5177c436f032666c572df97ab591cc6ac2da96ab6818a2f38d72b430aebbdc0a",
            ),
            (
                "b9c5610a07f4344b27625155614fb1341dd0392c68482f101b820bc1e2b908e5",
                "0df7c88054ae3c5f75c364257d064f42d660e6ea1184bd2a3af0d7455cb4e9ee",
            ),
            "48fRSJiQSp3Da61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xTungkh5",
        ),
    ];

    #[test]
    fn test_new() {
        let (seed, (private_spend_key, private_view_key), (public_spend_key, public_view_key), address) = KEYPAIRS[0];
        let public = MoneroPublicKey::<N>::from(public_spend_key, public_view_key, FORMAT).unwrap();
        let private = MoneroPrivateKey::<N>::from_seed(seed, FORMAT).unwrap();

        let mut rand: [u8; 32] = [0u8; 32];
        rand.copy_from_slice(hex::decode(seed).unwrap().as_slice());

        let index = 1;
        let one_time_key = OneTimeKey::new(&public, rand, index);
        println!("one time public key    {:?}", hex::encode(one_time_key.to_destination_key()));
        println!("transaction public key {:?}", hex::encode(one_time_key.to_transaction_public_key()));
        println!("receiver private key   {:?}", hex::encode(one_time_key.to_private(&private, index)));
        println!("receiver public key    {:?}", hex::encode(one_time_key.to_public(&private, index)));
        assert!(one_time_key.verify(&private, index));
    }
}
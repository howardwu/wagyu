use crate::address::Format;
use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use crate::transaction::MoneroTransaction;
use wagyu_model::{one_time_key::OneTimeKeyError, PublicKeyError};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsBasepointTable, scalar::Scalar};
use std::marker::PhantomData;

/// Represents a one time key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub fn new(public: &MoneroPublicKey<N>, rand: &[u8; 32], index: u64) -> Result<OneTimeKey<N>, OneTimeKeyError> {
        //key = hash(ra || n)G + b
        //one_time_key = hash((random * public_view_key) || index) * generator + public_spend_key
        const G: &EdwardsBasepointTable = &ED25519_BASEPOINT_TABLE;

        let public_spend_key: [u8; 32] = match public.to_public_spend_key() {
            Some(key) => key,
            None => return Err(OneTimeKeyError::PublicKeyError(PublicKeyError::NoSpendingKey)),
        };
        let public_view_key: [u8; 32] = match public.to_public_view_key() {
            Some(key) => key,
            None => return Err(OneTimeKeyError::PublicKeyError(PublicKeyError::NoViewingKey)),
        };

        let public_spend_point = &match CompressedEdwardsY::from_slice(&public_spend_key).decompress() {
            Some(point) => point,
            None => return Err(OneTimeKeyError::EdwardsPointError(public_spend_key)),
        };
        let mut concat = Vec::<u8>::new();

        MoneroTransaction::<N>::generate_key_derivation(
            &public_view_key,
            &rand,
            &mut concat
        )?;

        let hash = &MoneroTransaction::<N>::derivation_to_scalar(&mut concat, index);
        let key: EdwardsPoint = hash * G + public_spend_point;

        let tx = &Scalar::from_bits(*rand) * G;

        Ok(Self {
            destination_key: key.compress().to_bytes(),
            transaction_public_key: tx.compress().to_bytes(),
            _network: PhantomData,
        })
    }

    /// Returns the one time private key given recipient private keys
    pub fn to_private(&self, private: &MoneroPrivateKey<N>, index: u64) -> Result<[u8; 32], OneTimeKeyError> {
        //x = H_s(aR || n) + b
        let mut concat = Vec::<u8>::new();
        let private_spend_scalar = Scalar::from_bits(private.to_private_spend_key());

        MoneroTransaction::<N>::generate_key_derivation(
            &self.to_transaction_public_key(),
            &private.to_private_view_key(),
            &mut concat)?;

        let hash = MoneroTransaction::<N>::derivation_to_scalar(&mut concat, index);
        let x: Scalar = hash + private_spend_scalar;

        Ok(x.to_bytes())
    }

    /// Returns one time public key given recipient private keys for verification
    pub fn to_public(&self, private: &MoneroPrivateKey<N>, index: u64) -> Result<[u8; 32], OneTimeKeyError> {
        //P = (H_s(aR || n) + b) * G
        const G: &EdwardsBasepointTable = &ED25519_BASEPOINT_TABLE;
        let one_time_private_key = self.to_private(private, index)?;
        let one_time_public_key = &Scalar::from_bits(one_time_private_key) * G;

        Ok(one_time_public_key.compress().to_bytes())
    }

    /// Verifies that the one time public key can be generated from recipient private keys
    pub fn verify(&self, private: &MoneroPrivateKey<N>, index: u64) -> Result<bool, OneTimeKeyError> {
        let expected = self.to_public(private, index)?;

        Ok(self.to_destination_key() == expected)
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
    use crate::{
        Mainnet,
    };
    use hex;

    type N = Mainnet;

    const FORMAT: &Format = &Format::Standard;

    // (rand, (private_spend_key, private_view_key), (public_spend_key, public_view_key), address, random_str, output_index)
    const KEYPAIRS: [(&str, (&str, &str), (&str, &str), &str, &str, &str); 1] = [
        // test vector from https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-part-2-stealth-addresses
        // generated from https://xmr.llcoins.net/
        (
            "c595161ea20ccd8c692947c2d3ced471e9b13a18b150c881232794e8042bf107",
            (
                "c595161ea20ccd8c692947c2d3ced471e9b13a18b150c881232794e8042bf107",
                "fadf3558b700b88936113be1e5342245bd68a6b1deeb496000c4148ad4b61f02",
            ),
            (
                "3bcb82eecc13739b463b386fc1ed991386a046b478bf4864673ca0a229c3cec1",
                "6bb8297dc3b54407ac78ffa4efa4afbe5f1806e5e41aa56ae98c2fe53032bb4b",
            ),
            "43tXwm6UNNvSyMdHU4Jfeg4GRgU7KEVAfHo3B5RrXYMjZMRaowr68y12HSo14wv2qcYqqpG1U5AHrJtBdFHKPDEA9UxK6Hy",
            "c91ae3053f640fcad393fb6c74ad9f064c25314c8993c5545306154e070b1f0f",
            "0",
        ),
    ];

    fn test_new(
        receiver_public_key: &MoneroPublicKey<N>,
        receiver_private_key: &MoneroPrivateKey<N>,
        random_bytes: &[u8; 32],
        output_index: u64,
    ) {
        let one_time_key = OneTimeKey::new(receiver_public_key, random_bytes, output_index).unwrap();

        println!(
            "one time public key    {:?}",
            hex::encode(one_time_key.to_destination_key())
        );
        println!(
            "transaction public key {:?}",
            hex::encode(one_time_key.to_transaction_public_key())
        );
        println!(
            "receiver private key   {:?}",
            hex::encode(one_time_key.to_private(receiver_private_key, output_index).unwrap())
        );
        println!(
            "receiver public key    {:?}",
            hex::encode(one_time_key.to_public(receiver_private_key, output_index).unwrap())
        );

        assert!(one_time_key.verify(receiver_private_key, output_index).unwrap());
    }

    #[test]
    fn new() {
        KEYPAIRS.iter().for_each(
            |(_, (private_spend_key, _), (public_spend_key, public_view_key), _, random_str, output_index)| {
                let public_key = MoneroPublicKey::<N>::from(public_spend_key, public_view_key, FORMAT).unwrap();
                let private_key = MoneroPrivateKey::<N>::from_private_spend_key(private_spend_key, FORMAT).unwrap();

                let mut random_bytes: [u8; 32] = [0u8; 32];
                random_bytes.copy_from_slice(hex::decode(random_str).unwrap().as_slice());

                let index: u64 = output_index.parse::<u64>().unwrap();


                test_new(&public_key, &private_key, &random_bytes, index);
            },
        );
    }
}

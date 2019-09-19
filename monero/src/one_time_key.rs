#![allow(non_snake_case)]

use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use wagyu_model::{PublicKeyError, TransactionError};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsBasepointTable, scalar::Scalar};
use tiny_keccak::keccak256;
use std::marker::PhantomData;

#[derive(Debug, Fail)]
pub enum OneTimeKeyError {
    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "could not generate Edwards point from slice {:?}", _0)]
    EdwardsPointError([u8; 32]),

    #[fail(display = "{}", _0)]
    PublicKeyError(PublicKeyError),

    #[fail(display = "{}", _0)]
    TransactionError(TransactionError),
}

impl From<PublicKeyError> for OneTimeKeyError {
    fn from(error: PublicKeyError) -> Self {
        OneTimeKeyError::PublicKeyError(error)
    }
}

impl From<TransactionError> for OneTimeKeyError {
    fn from(error: TransactionError) -> Self {
        OneTimeKeyError::TransactionError(error)
    }
}

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
        //destination_key = hash((random * public_view_key) || index) * generator + public_spend_key
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

        Self::generate_key_derivation(
            &public_view_key,
            &rand,
            &mut concat,
        )?;

        let hash = &Self::derivation_to_scalar(&mut concat, index);
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
        //one_time_private_key = hash((private_view_key * transaction_public_key) || index) + private_spend_key
        let mut concat = Vec::<u8>::new();

        Self::generate_key_derivation(
            &self.to_transaction_public_key(),
            &private.to_private_view_key(),
            &mut concat)?;

        let hash = Self::derivation_to_scalar(&mut concat, index);
        let private_spend_scalar = Scalar::from_bits(private.to_private_spend_key());
        let x: Scalar = hash + private_spend_scalar;

        Ok(x.to_bytes())
    }

    /// Returns one time public destination key given recipient private keys for verification
    fn to_public(&self, private: &MoneroPrivateKey<N>, index: u64) -> Result<[u8; 32], OneTimeKeyError> {
        //destination_key = one_time_private_key * G
        const G: &EdwardsBasepointTable = &ED25519_BASEPOINT_TABLE;
        let one_time_private_key = self.to_private(private, index)?;
        let destination_key = &Scalar::from_bits(one_time_private_key) * G;

        Ok(destination_key.compress().to_bytes())
    }

    /// Verifies that the one time public key can be generated from recipient private keys
    pub fn verify(&self, private: &MoneroPrivateKey<N>, index: u64) -> Result<bool, OneTimeKeyError> {
        let expected = self.to_public(private, index)?;

        Ok(self.to_destination_key() == expected)
    }

    /// Encodes the index to conform to Monero consensus
    fn encode_varint(index: u64) -> Vec<u8> {
        // used here: https://github.com/monero-project/monero/blob/50d48d611867ffcd41037e2ab4fec2526c08a7f5/src/crypto/crypto.cpp#L195
        // impl here: https://github.com/monero-project/monero/blob/50d48d611867ffcd41037e2ab4fec2526c08a7f5/src/common/varint.h#L69
        let mut res: Vec<u8> = vec![];
        let mut n = index;
        loop {
            let bits = (n & 0b0111_1111) as u8;
            n = n >> 7;
            res.push(bits);
            if n == 0u64 {
                break;
            }
        }
        let mut encoded_bytes = vec![];
        match res.split_last() {
            Some((last, arr)) => {
                let _a: Vec<_> = arr
                    .iter()
                    .map(|bits| encoded_bytes.push(*bits | 0b1000_0000))
                    .collect();
                encoded_bytes.push(*last);
            }
            None => encoded_bytes.push(0x00),
        }

        encoded_bytes
    }

    /// Returns scalar base multiplication of public and secret key then multiplies result by cofactor
    fn generate_key_derivation(public: &[u8; 32], secret_key: &[u8; 32], dest: &mut Vec<u8>) -> Result<(), OneTimeKeyError> {
        // r * A
        let r = Scalar::from_bits(*secret_key);
        let A = &match CompressedEdwardsY::from_slice(public).decompress() {
            Some(point) => point,
            None => return Err(OneTimeKeyError::EdwardsPointError(*public)),
        };

        let mut rA: EdwardsPoint = r * A;
        rA = rA.mul_by_cofactor(); //https://github.com/monero-project/monero/blob/50d48d611867ffcd41037e2ab4fec2526c08a7f5/src/crypto/crypto.cpp#L182

        dest.clear();
        dest.extend(rA.compress().to_bytes().to_vec());

        Ok(())
    }

    /// Returns keccak256 hash of key derivation extended by output index as a scalar
    fn derivation_to_scalar(derivation: &Vec<u8>, output_index: u64) -> Scalar {
        // H_s(derivation || output_index)
        let mut derivation = derivation.clone();
        derivation.extend(&Self::encode_varint(output_index));

        Scalar::from_bytes_mod_order(keccak256(&derivation))
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
    use crate::format::MoneroFormat;
    use crate::Mainnet;
    use hex;

    type N = Mainnet;

    const FORMAT: &MoneroFormat = &MoneroFormat::Standard;

    // (
    //      sender_private_spend_key,
    //      (
    //          receiver_public_spend_key,
    //          receiver_public_view_key
    //      ),
    //      random_string,
    //      output_index,
    //      (
    //          one_time_public_key,
    //          one_time_private_key
    //      ),
    //      transaction_public_key
    // )
    const KEYPAIRS: [(&str, (&str, &str), &str, &str, (&str, &str), &str); 1] = [
        // generated from https://xmr.llcoins.net/
        (
            "c595161ea20ccd8c692947c2d3ced471e9b13a18b150c881232794e8042bf107",
            (
                "3bcb82eecc13739b463b386fc1ed991386a046b478bf4864673ca0a229c3cec1",
                "6bb8297dc3b54407ac78ffa4efa4afbe5f1806e5e41aa56ae98c2fe53032bb4b",
            ),
            "c91ae3053f640fcad393fb6c74ad9f064c25314c8993c5545306154e070b1f0f",
            "0",
            (
                "6cabaac48d3b9043525a703e9e5feb72132f69ea6deca9b4acf9228beb74cd8f",
                "97df43cb906896405a8b54ecd4610c92b99de5090b404e5e64b17af17da01601",
            ),
            "396fc23bc389046b214087a9522c0fbd673d2f3f00ab9768f35fa52f953fef22",
        ),
    ];

    fn test_new(
        receiver_public_key: &MoneroPublicKey<N>,
        receiver_private_key: &MoneroPrivateKey<N>,
        random_bytes: &[u8; 32],
        output_index: u64,
        one_time_public_key: &'static str,
        one_time_private_key: &'static str,
        transaction_public_key: &'static str,
    ) {
        let one_time_key = OneTimeKey::new(receiver_public_key, random_bytes, output_index).unwrap();

        assert_eq!(
            hex::encode(one_time_key.to_destination_key()),
            one_time_public_key
        );
        assert_eq!(
            hex::encode(one_time_key.to_transaction_public_key()),
            transaction_public_key
        );
        assert_eq!(
            hex::encode(one_time_key.to_private(receiver_private_key, output_index).unwrap()),
            one_time_private_key
        );

        assert!(one_time_key.verify(receiver_private_key, output_index).unwrap());
    }

    #[test]
    fn new() {
        KEYPAIRS.iter().for_each(|(
                                      sender_private_spend_key,
                                      (receiver_public_spend_key, receiver_public_view_key),
                                      random_str,
                                      output_index,
                                      (one_time_public_key, one_time_private_key),
                                      transaction_public_key)| {
            let public_key = MoneroPublicKey::<N>::from(receiver_public_spend_key, receiver_public_view_key, FORMAT).unwrap();
            let private_key = MoneroPrivateKey::<N>::from_private_spend_key(sender_private_spend_key, FORMAT).unwrap();

            let mut random_bytes: [u8; 32] = [0u8; 32];
            random_bytes.copy_from_slice(hex::decode(random_str).unwrap().as_slice());

            let index: u64 = output_index.parse::<u64>().unwrap();


            test_new(&public_key, &private_key, &random_bytes, index, one_time_public_key, one_time_private_key, transaction_public_key);
        });
    }
}

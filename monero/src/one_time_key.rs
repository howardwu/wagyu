use crate::address::Format;
use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use wagyu_model::private_key::PrivateKey;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use std::marker::PhantomData;
use tiny_keccak::keccak256;

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
    pub fn new(public: &MoneroPublicKey<N>, rand: [u8; 32], index: u64) -> OneTimeKey<N> {
        //P = H_s(rA || n)G + B
        let r = Scalar::from_bits(rand);
        let A = CompressedEdwardsY::from_slice(&public.to_public_view_key())
            .decompress()
            .unwrap(); //TODO: remove unwraps
        let B = CompressedEdwardsY::from_slice(&public.to_public_spend_key())
            .decompress()
            .unwrap();

        let mut rA: EdwardsPoint = r * A;
        rA = rA.mul_by_cofactor(); //https://github.com/monero-project/monero/blob/50d48d611867ffcd41037e2ab4fec2526c08a7f5/src/crypto/crypto.cpp#L182
        let mut concat: Vec<u8> = rA.compress().to_bytes().to_vec();
        concat.extend(&OneTimeKey::<N>::encode_varint(index));

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

    /// Returns the one time private key given recipient private keys
    pub fn to_private(&self, private: &MoneroPrivateKey<N>, index: u64) -> [u8; 32] {
        //x = H_s(aR || n) + b
        let R = CompressedEdwardsY(self.to_transaction_public_key())
            .decompress()
            .unwrap();
        let a = Scalar::from_bits(private.to_private_view_key());
        let b = Scalar::from_bits(private.to_private_spend_key());

        let mut aR: EdwardsPoint = a * R;
        aR = aR.mul_by_cofactor();
        let mut concat: Vec<u8> = aR.compress().to_bytes().to_vec();
        concat.extend(&OneTimeKey::<N>::encode_varint(index));

        let H_s = Scalar::from_bytes_mod_order(keccak256(&concat));
        let x: Scalar = H_s + b;

        x.to_bytes()
    }

    /// Returns one time public key given recipient private keys
    pub fn to_public(&self, private: &MoneroPrivateKey<N>, index: u64) -> [u8; 32] {
        //P = (H_s(aR || n) + b) * G
        let one_time_private_key = self.to_private(private, index);
        let P = &Scalar::from_bits(one_time_private_key) * &ED25519_BASEPOINT_TABLE;

        P.compress().to_bytes()
    }

    /// Verifies that the one time public key can be generated from recipient private keys
    pub fn verify(&self, private: &MoneroPrivateKey<N>, index: u64) -> bool {
        let expected = self.to_public(private, index);

        self.to_destination_key() == expected
    }

    pub fn to_destination_key(&self) -> [u8; 32] {
        self.destination_key
    }

    pub fn to_transaction_public_key(&self) -> [u8; 32] {
        self.transaction_public_key
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mainnet;
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
        random_bytes: [u8; 32],
        output_index: u64,
    ) {
        let one_time_key = OneTimeKey::new(receiver_public_key, random_bytes, output_index);

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
            hex::encode(one_time_key.to_private(receiver_private_key, output_index))
        );
        println!(
            "receiver public key    {:?}",
            hex::encode(one_time_key.to_public(receiver_private_key, output_index))
        );

        assert!(one_time_key.verify(receiver_private_key, output_index));
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

                test_new(&public_key, &private_key, random_bytes, index);
            },
        );
    }
}

use model::crypto::{checksum, hash160};
use crate::private_key::BitcoinPrivateKey;
use crate::extended_public_key::BitcoinExtendedPublicKey;
use crate::network::Network;

use base58::ToBase58;
use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Sha512;

use std::fmt;

//use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Bitcoin Extended Private Key
//#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BitcoinExtendedPrivateKey {
    /// The BitcoinPrivateKey
    pub private_key: BitcoinPrivateKey,

    /// The chain code corresponding to this extended private key.
    pub chain_code: [u8; 32],

    /// The network this extended private key can be used on.
    pub network: Network,

    /// 0x00 for master nodes, 0x01 for level-1 derived keys, ....
    pub depth: u8,

    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    pub parent_fingerprint: [u8; 4],

    /// This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    pub child_number: u32,
}

impl BitcoinExtendedPrivateKey {
    /// Generates new extended private key
    pub fn new(seed: &[u8]) -> Self {
        BitcoinExtendedPrivateKey::generate_master(seed)
    }

    /// Generates new master extended private key
    pub fn generate_master(seed: &[u8]) -> Self {
        let mut mac = HmacSha512::new_varkey(b"Bitcoin seed").expect("Error generating hmac");
        mac.input(seed);
        let result = mac.result().code();
        let (private_key, chain_code) = BitcoinExtendedPrivateKey::derive_private_key_and_chain_code(&result);
        Self {
            private_key,
            chain_code,
            network: Network::Mainnet,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0x00000000,
        }
    }

    /// Generates the child extended private key at child_number from the current extended private key
    pub fn ckd_priv(&self, child_number: u32) -> Self {

        let mut mac = HmacSha512::new_varkey(
            &self.chain_code).expect("error generating hmac from chain code");
        let public_key_serialized = &PublicKey::from_secret_key(
            &Secp256k1::new(), &self.private_key.secret_key).serialize()[..];

        // Check whether i ≥ 2^31 (whether the child is a hardened key).
        // If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)). (Note: The 0x00 pads the private key to make it 33 bytes long.)
        // If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
        if child_number >= 2_u32.pow(31) {
            let mut private_key_bytes = [0u8; 33];
            private_key_bytes[1..33].copy_from_slice(&self.private_key.secret_key[..]);
            mac.input(&private_key_bytes[..]);
        } else {
            mac.input(public_key_serialized);
        }

        let mut child_num_big_endian = [0u8; 4];
        BigEndian::write_u32(&mut child_num_big_endian, child_number);
        mac.input(&child_num_big_endian);

        let result = mac.result().code();

        let (mut private_key, chain_code) = BitcoinExtendedPrivateKey::derive_private_key_and_chain_code(&result);
        private_key.secret_key.add_assign(&Secp256k1::new(), &self.private_key.secret_key).expect("error add assign");

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

        Self {
            private_key,
            chain_code,
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,

        }
    }

    /// Generates the extended public key associated with the current extended private key
    pub fn to_pub(&self) -> BitcoinExtendedPublicKey {
        BitcoinExtendedPublicKey::from_private(&self)
    }

    /// Generates extended private key from Secp256k1 secret key, chain code, and network
    pub fn derive_private_key_and_chain_code(result: &[u8]) -> (BitcoinPrivateKey, [u8; 32]) {
        let private_key = BitcoinPrivateKey::from_secret_key(
            SecretKey::from_slice(&Secp256k1::without_caps(), &result[0..32]).expect("error generating secret key"),
            &Network::Mainnet,
            true
        );

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);

        return (private_key, chain_code);
    }
}

impl fmt::Display for BitcoinExtendedPrivateKey {
    /// BIP32 serialization format: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(&match self.network {
            Network::Mainnet => [0x04, 0x88, 0xAD, 0xE4],
            Network::Testnet => [0x04, 0x35, 0x83, 0x94],
        }[..]);
        result[4] = self.depth as u8;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        BigEndian::write_u32(&mut result[9..13], u32::from(self.child_number));

        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45] = 0;
        result[46..78].copy_from_slice(&self.private_key.secret_key[..]);

        let sum = &checksum(&result[0..78])[0..4];
        result[78..82].copy_from_slice(&sum);

        fmt.write_str(&result.to_base58())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    /// Test vectors from https://en.bitcoin.it/wiki/BIP_0032_TestVectors
    const SEED_STR: &str = "000102030405060708090a0b0c0d0e0f";
    const M_SECRET_KEY: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    const M_CHAIN_CODE: &str = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
    const M_PARENT_FINGERPRINT: &str = "00000000";
    const M_XPRIV_SERIALIZED: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const M_XPUB_SERIALIZED: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    const M0H_SECRET_KEY: &str = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
    const M0H_CHAIN_CODE: &str = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";
    const M0H_PARENT_FINGERPRINT: &str = "3442193e";
    const M0H_XPRIV_SERIALIZED: &str = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
    const M0H_XPUB_SERIALIZED : &str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";


    #[test]
    fn test_new() {
        let seed = hex::decode(SEED_STR).unwrap();
        let xpriv = BitcoinExtendedPrivateKey::new(&seed);
        assert_eq!(xpriv.private_key.secret_key.to_string(), M_SECRET_KEY);
        assert_eq!(hex::encode(xpriv.chain_code), M_CHAIN_CODE);
        assert_eq!(xpriv.depth, 0);
        assert_eq!(hex::encode(xpriv.parent_fingerprint), M_PARENT_FINGERPRINT);
        assert_eq!(xpriv.child_number, 0);
        assert_eq!(xpriv.to_string(), M_XPRIV_SERIALIZED);
    }

    #[test]
    fn test_to_pub() {
        let seed = hex::decode(SEED_STR).unwrap();
        let xpriv = BitcoinExtendedPrivateKey::new(&seed);
        let xpub = xpriv.to_pub();
        assert_eq!(xpub.to_string(), M_XPUB_SERIALIZED);
    }

    #[test]
    fn test_ckd_priv_m0h() {
        let seed = hex::decode(SEED_STR).unwrap();
        let parent_xpriv = BitcoinExtendedPrivateKey::new(&seed);
        let child_xpriv = parent_xpriv.ckd_priv(2_u32.pow(31));
        let child_xpub = child_xpriv.to_pub();
        assert_eq!(hex::encode(child_xpriv.parent_fingerprint), M0H_PARENT_FINGERPRINT);
        assert_eq!(child_xpriv.private_key.secret_key.to_string(), M0H_SECRET_KEY);
        assert_eq!(hex::encode(child_xpriv.chain_code), M0H_CHAIN_CODE);
        assert_eq!(child_xpriv.to_string(), M0H_XPRIV_SERIALIZED);
        assert_eq!(child_xpub.to_string(), M0H_XPUB_SERIALIZED);
    }
}
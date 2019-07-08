use model::crypto::{checksum, hash160};
use crate::extended_private_key::BitcoinExtendedPrivateKey;
use crate::network::Network;

use base58::ToBase58;
use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;
use std::fmt;
//use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Bitcoin extended public key
pub struct BitcoinExtendedPublicKey {
    /// The Secp256k1 public key associated with a BitcoinExtendedPrivateKey's private_key
    pub public_key: PublicKey,

    /// The chain code associated with a BitcoinExtendedPrivateKey
    pub chain_code: [u8; 32],

    /// the network this extended public key can be used on
    pub network: Network,

    /// 0x00 for master nodes, 0x01 for level-1 derived keys, ....
    pub depth: u8,

    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    pub parent_fingerprint: [u8; 4],

    /// This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    pub child_number: u32,
}

impl BitcoinExtendedPublicKey {
    /// Returns extended public key given extended private key
    pub fn from_private(private_key: &BitcoinExtendedPrivateKey) -> Self {
        Self {
            public_key: PublicKey::from_secret_key(&Secp256k1::new(), &private_key.private_key.secret_key),
            chain_code: private_key.chain_code,
            network: private_key.network,
            depth: private_key.depth,
            parent_fingerprint: private_key.parent_fingerprint,
            child_number: private_key.child_number,
        }
    }

    /// Generates a child extended public key at child_number from the current extended private key
    pub fn ckd_pub(&self, child_number: u32) -> Self {

        let mut mac = HmacSha512::new_varkey(
            &self.chain_code).expect("error generating hmac");
        let public_key_serialized = &self.public_key.serialize()[..];

        // Check whether i ≥ 231 (whether the child is a hardened key).
        // If so (hardened child): return failure
        // If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
        if child_number >= 2_u32.pow(31) {
            panic!("Cannot derive hardened child from extended public key")
        } else {
            mac.input(public_key_serialized);
        }

        let mut child_num_big_endian = [0; 4];
        BigEndian::write_u32(&mut child_num_big_endian, child_number);
        mac.input(&child_num_big_endian);

        let result = mac.result().code();

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);

        let secret_key = SecretKey::from_slice(
            &Secp256k1::without_caps(),
            &result[..32]).expect("error generating secret key");
        let mut public_key = self.public_key.clone();
        public_key.add_exp_assign(&Secp256k1::new(), &secret_key).expect("error exp assign");

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

        Self {
            public_key,
            chain_code,
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,
        }
    }
}

impl fmt::Display for BitcoinExtendedPublicKey {
    /// BIP32 serialization format: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(&match self.network {
            Network::Mainnet => [0x04u8, 0x88, 0xB2, 0x1E],
            Network::Testnet => [0x04u8, 0x35, 0x87, 0xCF],
        }[..]);
        result[4] = self.depth as u8;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        BigEndian::write_u32(&mut result[9..13], u32::from(self.child_number));

        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45..78].copy_from_slice(&self.public_key.serialize()[..]);

        let sum = &checksum(&result[0..78])[0..4];
        result[78..82].copy_from_slice(sum);

        fmt.write_str(&result.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    /// Test vectors from https://en.bitcoin.it/wiki/BIP_0032_TestVectors
    const SEED_STR : &str = "000102030405060708090a0b0c0d0e0f";
    const M_XPUB_SERIALIZED: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const M0_XPUB_SERIALIZED: &str = "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1";
    #[test]
    fn test_from_private() {
        let seed = hex::decode(SEED_STR).unwrap();
        let xpriv = BitcoinExtendedPrivateKey::new(&seed);
        let xpub = BitcoinExtendedPublicKey::from_private(&xpriv);
        println!("{}", xpub.to_string());
        assert_eq!(xpub.to_string(), M_XPUB_SERIALIZED);
    }

    #[test]
    fn test_ckd_pub_m0() {
        let seed = hex::decode(SEED_STR).unwrap();
        let xpriv = BitcoinExtendedPrivateKey::new(&seed);
        let child_xpriv = xpriv.ckd_priv(0);
        let expected_child_xpub = child_xpriv.to_pub().to_string();

        let xpub = BitcoinExtendedPublicKey::from_private(&xpriv);
        let child_xpub = xpub.ckd_pub(0).to_string();
        assert_eq!(child_xpub, expected_child_xpub);
        assert_eq!(child_xpub, M0_XPUB_SERIALIZED);
    }
}
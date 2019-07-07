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

    /// Generates a normal child extended public key
    pub fn ckd_pub(&self, child_number: u32) -> Self {

        // let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)). serP(point(kpar)) ~ Secp256k1_PublicKey.serialize()
        let mut mac = HmacSha512::new_varkey(&self.chain_code).expect("error generating hmac");
        let public_key_serialized = &self.public_key.serialize()[..];
        mac.input(public_key_serialized);

        let mut child_num_big_endian = [0; 4];
        BigEndian::write_u32(&mut child_num_big_endian, child_number);
        mac.input(&child_num_big_endian);

        let result = mac.result().code();

        let secret_key = SecretKey::from_slice(&Secp256k1::without_caps(), &result[..32]).expect("error generating secret key");
        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);
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
        let mut result = [0; 82];
        result[0..4].copy_from_slice(&match self.network {
            Network::Mainnet => [0x04u8, 0x88, 0xB2, 0x1E],
            Network::Testnet => [0x04u8, 0x35, 0x87, 0xCF],
        }[..]);
        result[4] = self.depth as u8;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        BigEndian::write_u32(&mut result[9..13], u32::from(self.child_number));

        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45..78].copy_from_slice(&self.public_key.serialize()[..]);

        let sum = &checksum(&result[..])[0..4];
        result[78..82].copy_from_slice(sum);

        fmt.write_str(&result.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_from_private() {
        let seed = hex::decode("2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607").unwrap();
        let expected_xpub = "xpub661MyMwAqRbcFAEb7d5FeyQpgzpW1yk1koNRtHHhuayKXL7Ls2Kg3GdMzWHSDAfpkzzxKfB9pDHeF8iWTcnovFuJ4DYPBbPBWq7oUDhk4xB";
        let xpriv = BitcoinExtendedPrivateKey::new(&seed);
        let xpub = BitcoinExtendedPublicKey::from_private(&xpriv);
        println!("{}", xpub.to_string());
        assert_eq!(xpub.to_string(), expected_xpub);
    }
}
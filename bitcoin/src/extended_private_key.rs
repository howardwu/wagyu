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

    /// Generates a normal child extended private key
    pub fn ckd_priv(&self, child_number: u32) -> Self {

        // let result = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)). serP(point(kpar)) ~ Secp256k1_PublicKey.serialize()
        let mut mac = HmacSha512::new_varkey(&self.chain_code).expect("error generating hmac");
        let public_key_serialized = &PublicKey::from_secret_key(&Secp256k1::new(), &self.private_key.secret_key).serialize()[..];
        mac.input(public_key_serialized);

        let mut child_num_big_endian = [0; 4];
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

    /// Generates child extended public key
    pub fn ckd_pub(&self) -> BitcoinExtendedPublicKey {
        BitcoinExtendedPublicKey::from_private(&self)
    }

    /// Generates extended private key from Secp256k1 secret key, chain code, and network
    pub fn derive_private_key_and_chain_code(result: &[u8]) -> (BitcoinPrivateKey, [u8; 32]) {
        let private_key = BitcoinPrivateKey::from_secret_key(
            SecretKey::from_slice(&Secp256k1::without_caps(), &result[0..32]).expect("error generating secret key"),
            &Network::Mainnet,
        );

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);

        return (private_key, chain_code);
    }
}

impl fmt::Display for BitcoinExtendedPrivateKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut ret = [0; 82];
        ret[0..4].copy_from_slice(&match self.network {
            Network::Mainnet => [0x04, 0x88, 0xAD, 0xE4],
            Network::Testnet => [0x04, 0x35, 0x83, 0x94],
        }[..]);
        ret[4] = self.depth as u8;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[9..13], u32::from(self.child_number));

        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key.secret_key[..]);
        let sum = &checksum(&ret[..])[0..4];
        ret[78..82].copy_from_slice(sum);

        fmt.write_str(&ret.to_base58())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_new() {
        let seed = hex::decode("2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607").unwrap();
        let expected_xpriv = "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuPKSDB";
        let xpriv = BitcoinExtendedPrivateKey::new(&seed);
        println!("{}", xpriv.to_string());
        assert_eq!(xpriv.to_string(), expected_xpriv);
    }
}
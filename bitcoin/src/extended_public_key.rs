use crate::extended_private_key::BitcoinExtendedPrivateKey;
use crate::network::Network;

use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Bitcoin extended public key
pub struct BitcoinExtendedPublicKey {
    /// The Secp256k1 public key associated with a BitcoinExtendedPrivateKey's private_key
    pub public_key: PublicKey,

    /// The chain code associated with a BitcoinExtendedPrivateKey
    pub chain_code: [u8; 32],

    /// the network this extended public key can be used on
    pub network: Network,
}

impl BitcoinExtendedPublicKey {
    /// Returns extended public key given extended private key
    pub fn from_private(private_key: &BitcoinExtendedPrivateKey) -> Self {
        Self {
            public_key: PublicKey::from_secret_key(&Secp256k1::new(), &private_key.private_key.secret_key),
            chain_code: private_key.chain_code,
            network: private_key.network,
        }
    }

    /// Generates a normal child extended public key
    pub fn ckd_pub(&self) -> Self {
        // let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)). serP(point(kpar)) ~ Secp256k1_PublicKey.serialize()
        let mut mac = HmacSha512::new_varkey(&self.chain_code).expect("error generating hmac");
        mac.input(&self.public_key.serialize()[..]);
        let mut child_num_be = [0; 4];
        BigEndian::write_u32(&mut child_num_be, u32::from_str_radix("0", 16).expect("error ")); // hardcode fetch the 0th child for now
        mac.input(&child_num_be);

        let result = mac.result().code();
        let secret_key = SecretKey::from_slice(&Secp256k1::without_caps(), &result[..32]).expect("error generating secret key");
        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);

        Self {
            public_key: PublicKey::from_secret_key(&Secp256k1::new(), &secret_key),
            chain_code,
            network: self.network,
        }
    }
}
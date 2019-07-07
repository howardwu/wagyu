use crate::private_key::BitcoinPrivateKey;
use crate::extended_public_key::BitcoinExtendedPublicKey;
use crate::network::Network;

use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Bitcoin Extended Private Key
pub struct BitcoinExtendedPrivateKey {
    /// The BitcoinPrivateKey
    pub private_key: BitcoinPrivateKey,

    /// The chain code corresponding to this extended private key.
    pub chain_code: [u8; 32],

    /// The network this extended private key can be used on.
    pub network: Network,
}

impl BitcoinExtendedPrivateKey {
    /// Generates new extended private key
    pub fn new() -> Self {
        let mut mac = HmacSha512::new_varkey(b"bitcoin").expect("Error generating hmac");
        mac.input(b"seed");
        let result = mac.result().code();
        let network = Network::Mainnet;

        Self::generate_extended_private_key(
            &result[..32],
            &result[32..],
            network)
    }

    /// Generates extended private key from Secp256k1 secret key, chain code, and network
    pub fn generate_extended_private_key(
        secret_key_slice: &[u8],
        chain_code_slice: &[u8],
        network: Network,
    ) -> Self {
        let private_key = BitcoinPrivateKey::from_secret_key(
            SecretKey::from_slice(&Secp256k1::without_caps(), secret_key_slice).expect("error generating secret key"),
            &Network::Mainnet,
        );

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(chain_code_slice);

        Self { private_key, chain_code, network }
    }

    /// Generates a normal child extended private key
    pub fn ckd_priv(&self) -> Self {
        // let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)). serP(point(kpar)) ~ Secp256k1_PublicKey.serialize()
        let mut mac = HmacSha512::new_varkey(&self.chain_code).expect("error generating hmac");
        mac.input(&PublicKey::from_secret_key(&Secp256k1::new(), &self.private_key.secret_key).serialize()[..]);
        let mut child_num_be = [0; 4];
        BigEndian::write_u32(&mut child_num_be, u32::from_str_radix("0", 16).expect("error ")); // hardcode fetch the 0th child for now
        mac.input(&child_num_be);

        let result = mac.result().code();
        Self::generate_extended_private_key(
            &result[..32],
            &result[32..],
            self.network
        )
    }

    /// Generates child extended public key
    pub fn ckd_pub(&self) -> BitcoinExtendedPublicKey {
        BitcoinExtendedPublicKey::from_private(&self)
    }
}
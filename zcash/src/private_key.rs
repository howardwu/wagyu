use address::{ZcashAddress, Format};
use model::{Address, PrivateKey, PublicKey, crypto::checksum};
use network::{Network, MAINNET_BYTE, TESTNET_BYTE};
use public_key::ZcashPublicKey;

use base58::{FromBase58, ToBase58};
use rand::Rng;
use rand::rngs::OsRng;
use secp256k1::Secp256k1;
use secp256k1;
use std::{fmt, fmt::Display};
use std::str::FromStr;

/// Represents a Zcash Private Key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZcashPrivateKey {
    /// The ECDSA private key
    pub secret_key: secp256k1::SecretKey,
    /// The Wallet Import Format (WIF) string encoding
    pub wif: String,
    /// The network of the private key
    pub network: Network,
    /// If true, the private key is serialized in compressed form
    pub compressed: bool,
}

impl PrivateKey for ZcashPrivateKey {
    type Address = ZcashAddress;
    type Format = Format;
    type Network = Network;
    type PublicKey = ZcashPublicKey;

    /// Randomly generates a new compressed private key
     fn new(network: &Network) -> Self {
        Self::build(network, true)
    }

    /// Returns the Secp256k1 PublicKey generated from this PrivateKey
     fn to_public_key(&self) -> Self::PublicKey {
        ZcashPublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Zcash private key.
    fn to_address(&self, format: &Self::Format) -> Self::Address {
        ZcashAddress::from_private_key(self, format)
    }
}

impl ZcashPrivateKey {
    /// Returns a private key given a secp256k1 secret key
    pub fn from_secret_key(secret_key: secp256k1::SecretKey, network: &Network) -> Self {
        let compressed = secret_key.len() == 65;
        let wif = Self::secret_key_to_wif(&secret_key, network, compressed);

        Self { secret_key, wif, network: *network, compressed}
    }

    /// Returns a Result which holds either the PrivateKey corresponding to `wif` or an error
    pub fn from_wif(wif: &str) -> Result<Self, &'static str> {
        let wif_bytes = wif.from_base58().expect("Error decoding base58 wif");
        let wif_length = wif_bytes.len();

        let network = match wif_bytes[0] {
            MAINNET_BYTE => Network::Mainnet,
            TESTNET_BYTE=> Network::Testnet,
            _ => return Err("Invalid wif")
        };

        let wif_bytes_to_hash = &wif_bytes[0..wif_length - 4];
        let expected_checksum = &wif_bytes[wif_length - 4..];
        let is_valid_checksum = checksum(wif_bytes_to_hash)[0..4] == expected_checksum[0..4];

        match is_valid_checksum {
            true => {
                let secp = Secp256k1::without_caps();
                let secret_key = secp256k1::SecretKey::from_slice(&secp, &wif_bytes[1..33])
                    .expect("Error creating secret key from slice");
                Ok(
                    Self {
                        network,
                        wif: wif.to_string(),
                        secret_key,
                        compressed: wif_length == 38,
                    }
                )
            },
            false => Err("Invalid wif")
        }
    }

    /// Returns a randomly-generated Zcash private key.
    fn build(network: &Network, compressed: bool) -> Self {
        let secret_key = Self::generate_secret_key();
        let wif = Self::secret_key_to_wif(&secret_key, network, compressed);
        Self { secret_key, wif, network: *network, compressed }
    }

    /// Returns a randomly-generated a secp256k1 secret key.
    fn generate_secret_key() -> secp256k1::SecretKey {
        let secp = Secp256k1::new();
        let mut rand_bytes = [0u8; 32];
        OsRng.try_fill(&mut rand_bytes)
            .expect("Error generating random bytes for private key");
        secp256k1::SecretKey::from_slice(&secp, &rand_bytes)
            .expect("Error creating secret key from byte slice")
    }

    /// Returns a WIF string given a secp256k1 secret key.
    fn secret_key_to_wif(secret_key: &secp256k1::SecretKey, network: &Network, compressed: bool) -> String {
        let mut wif = [0u8; 38];
        wif[0] = match network {
            Network::Mainnet => MAINNET_BYTE,
            Network::Testnet => TESTNET_BYTE,
        };
        wif[1..33].copy_from_slice(&secret_key[..]);

        if compressed {
            wif[33] = 0x01;
            let checksum_bytes = checksum(&wif[0..34]);
            wif[34..].copy_from_slice(&checksum_bytes[0..4]); // Append Checksum Bytes
            wif.to_base58()
        } else {
            let checksum_bytes = checksum(&wif[0..33]);
            wif[33..37].copy_from_slice(&checksum_bytes[0..4]); // Append Checksum Bytes
            wif[..37].to_base58()
        }
    }
}

impl Default for ZcashPrivateKey {
    /// Returns a randomly-generated mainnet Zcash private key.
    fn default() -> Self { Self::new(&Network::Mainnet) }
}

impl FromStr for ZcashPrivateKey {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, &'static str> { Self::from_wif(s) }
}

impl Display for ZcashPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.wif) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Message;

    extern crate hex;

    fn test_from_wif(wif: &str, secret_key_string: &str) {
        let private_key = ZcashPrivateKey::from_wif(wif).expect("Error deriving private key from wif");
        let secp = Secp256k1::without_caps();
        let secret_key_as_bytes =
            hex::decode(secret_key_string).expect("Error decoding secret key from hex string");
        let secret_key = secp256k1::SecretKey::from_slice(&secp, &secret_key_as_bytes)
            .expect("Error deriving secret key from hex string");
        assert_eq!(private_key.secret_key, secret_key);
    }

    fn test_to_wif(secret_key_string: &str, wif: &str, network: &Network) {
        let secp = Secp256k1::without_caps();
        let secret_key_as_bytes =
            hex::decode(secret_key_string).expect("Error decoding secret key from hex string");
        let secret_key = secp256k1::SecretKey::from_slice(&secp, &secret_key_as_bytes)
            .expect("Error deriving secret key from hex string");
        let private_key = ZcashPrivateKey::from_secret_key(secret_key, network);
        assert_eq!(private_key.secret_key, secret_key);
        assert_eq!(private_key.wif, wif);
    }

    fn test_new(private_key: ZcashPrivateKey) {
        let first_character = match private_key.wif.chars().next() {
            Some(c) => c,
            None => panic!("Error unwrapping first character of WIF"),
        };
        // Reference: https://en.bitcoin.it/wiki/Address#Address_map
        let is_valid_first_character = match (private_key.network, private_key.compressed) {
            (Network::Mainnet, false) => first_character == '5',
            (Network::Testnet, false) => first_character == '9',
            (Network::Mainnet, true) => first_character == 'L' || first_character == 'K',
            (Network::Testnet, true) => first_character == 'c',
            _ => false,
        };
        assert!(is_valid_first_character);
        let from_wif =
            ZcashPrivateKey::from_wif(private_key.wif.as_str()).expect("Error unwrapping private key from WIF");
        assert_eq!(from_wif.wif, private_key.wif);
    }

    #[test]
    fn test_to_public_key() {
        let secp = Secp256k1::new();
        let private_key = ZcashPrivateKey::new(&Network::Mainnet);
        let public_key = private_key.to_public_key();
        let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

        let sig = secp.sign(&message, &private_key.secret_key);
        assert!(secp.verify(&message, &sig, &public_key.public_key).is_ok());
    }

    #[test]
    fn test_new_mainnet() {
        let private_key = ZcashPrivateKey::new(&Network::Mainnet);
        test_new(private_key);
    }

    #[test]
    fn test_new_testnet() {
        let private_key = ZcashPrivateKey::new(&Network::Testnet);
        test_new(private_key);
    }

//    #[test]
//    fn test_new_compressed_mainnet() {
//        let private_key = ZcashPrivateKey::new_compressed(Network::Mainnet);
//        test_new(private_key);
//    }
//
//    #[test]
//    fn test_new_compressed_testnet() {
//        let private_key = ZcashPrivateKey::new_compressed(Network::Testnet);
//        test_new(private_key);
//    }

    #[test]
    fn test_mainnet_from_wif() {
        test_from_wif(
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
            "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
        );
    }

    #[test]
    fn test_testnet_from_wif() {
        test_from_wif(
            "921YpFFoB1UN7tud1vne5hTrijX423MexQxYn6dmeHB25xT8c2s",
            "37EE08B51CB5932276DB785C8E23CC0FDC99A2923C7ECA43A6D3FD26D94EBD44",
        );
    }

    #[test]
    fn test_mainnet_to_wif() {
        test_to_wif(
            "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
            &Network::Mainnet,
        )
    }

    #[test]
    fn test_testnet_to_wif() {
        test_to_wif(
            "37EE08B51CB5932276DB785C8E23CC0FDC99A2923C7ECA43A6D3FD26D94EBD44",
            "921YpFFoB1UN7tud1vne5hTrijX423MexQxYn6dmeHB25xT8c2s",
            &Network::Testnet,
        )
    }
}

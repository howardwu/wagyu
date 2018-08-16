extern crate base58;
extern crate rand;
extern crate secp256k1;

use self::base58::{FromBase58, ToBase58};
use self::rand::thread_rng;
use self::rand::RngCore;
use self::secp256k1::Secp256k1;
use self::secp256k1::{PublicKey, SecretKey};
use network::{Network, MAINNET_BYTE, TESTNET_BYTE};
use std::fmt;
use utils::checksum;

/// Represents a Bitcoin Private Key
#[derive(Serialize, Debug, Eq, PartialEq)]
pub struct PrivateKey {
    /// The Secp256k1 SecretKey Object
    #[serde(skip_serializing,skip_deserializing)]
    secret_key: SecretKey,

    /// The PrivateKey in Wallet Import Format
    wif: String,

    /// Network this PrivateKey is for (Mainnet, Testnet)
    network: Network,

    /// If true, this PrivateKey corresponds to a compressed Public Key
    compressed: bool,
}

impl PrivateKey {
    /// Randomly generates a new uncompressed private key
    pub fn new(network: Network) -> PrivateKey {
        PrivateKey::build(network, false)
    }

    /// Randomly generates a new compressed private key
    pub fn new_compressed(network: Network) -> PrivateKey {
        PrivateKey::build(network, true)
    }

    fn build(network: Network, compressed: bool) -> PrivateKey {
        let secret_key = PrivateKey::generate_secret_key();
        let wif = PrivateKey::secret_key_to_wif(&secret_key, &network, compressed);

        PrivateKey {
            secret_key,
            wif,
            network,
            compressed,
        }
    }

    /// Randomly generate a Secp256k1 SecretKey
    fn generate_secret_key() -> SecretKey {
        let secp = Secp256k1::new();
        let mut rand_bytes = [0u8; 32];
        let mut rng = thread_rng();
        rng.try_fill_bytes(&mut rand_bytes)
            .expect("Error generating random bytes for private key");

        SecretKey::from_slice(&secp, &rand_bytes)
            .expect("Error creating secret key from byte slice")
    }

    /// Returns the Secp256k1 PublicKey generated from this PrivateKey
    pub fn to_public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &self.secret_key)
    }

    /// Creates a PrivateKey from a Secp256k1 SecretKey for the specified network
    pub fn from_secret_key(secret_key: SecretKey, network: Network) -> PrivateKey {
        let compressed = secret_key.len() == 65;
        let wif = PrivateKey::secret_key_to_wif(&secret_key, &network, compressed);

        PrivateKey {
            secret_key,
            wif,
            network,
            compressed,
        }
    }

    /// Convert Secp256k1 SecretKey to PrivateKey WIF String
    fn secret_key_to_wif(secret_key: &SecretKey, network: &Network, compressed: bool) -> String {
        let mut wif = [0u8; 38];
        wif[0] = match network {
            // Prepend network byte
            Network::Testnet => TESTNET_BYTE,
            _ => MAINNET_BYTE,
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

    /// Returns a Result which holds either the PrivateKey corresponding to `wif` or an error
    pub fn from_wif(wif: &str) -> Result<PrivateKey, &'static str> {
        let wif_bytes = wif.from_base58().expect("Error decoding base58 wif");
        let length = wif_bytes.len();
        let compressed = length == 38;
        let expected_checksum = &wif_bytes[length - 4..];
        let network = match wif_bytes[0] {
            MAINNET_BYTE => Network::Mainnet,
            TESTNET_BYTE => Network::Testnet,
            _ => Network::Error,
        };

        let wif_bytes_to_hash = &wif_bytes[0..length - 4];

        let actual_checksum = checksum(wif_bytes_to_hash);

        let is_valid_checksum = actual_checksum[0..4] == expected_checksum[0..4];
        if !is_valid_checksum || network == Network::Error {
            Err("Invalid wif")
        } else {
            let secp = Secp256k1::without_caps();
            let secret_key = SecretKey::from_slice(&secp, &wif_bytes[1..33])
                .expect("Error creating secret key from slice");

            Ok(PrivateKey {
                network,
                wif: wif.to_string(),
                secret_key,
                compressed,
            })
        }
    }

    /// Returns an immutable reference to this PrivateKey's Secp256k1 SecretKey
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Returns an immutable reference to this PrivateKey's wif
    pub fn wif(&self) -> &String {
        &self.wif
    }

    /// Returns an immutable reference to this PrivateKey's Network
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// Returns true if the PrivateKey is compressed
    pub fn compressed(&self) -> &bool {
        &self.compressed
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Private Key in Wallet Import Format: {}", self.wif())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate hex;

    fn test_from_wif(wif: &str, secret_key_string: &str) {
        let private_key = PrivateKey::from_wif(wif).expect("Error deriving private key from wif");
        let secp = Secp256k1::without_caps();
        let secret_key_as_bytes =
            hex::decode(secret_key_string).expect("Error decoding secret key from hex string");
        let secret_key = SecretKey::from_slice(&secp, &secret_key_as_bytes)
            .expect("Error deriving secret key from hex string");
        assert_eq!(private_key.secret_key, secret_key);
    }

    fn test_to_wif(secret_key_string: &str, wif: &str, network: Network) {
        let secp = Secp256k1::without_caps();
        let secret_key_as_bytes =
            hex::decode(secret_key_string).expect("Error decoding secret key from hex string");
        let secret_key = SecretKey::from_slice(&secp, &secret_key_as_bytes)
            .expect("Error deriving secret key from hex string");
        let private_key = PrivateKey::from_secret_key(secret_key, network);
        assert_eq!(private_key.secret_key, secret_key);
        assert_eq!(private_key.wif(), wif);
    }

    fn test_new(private_key: PrivateKey) {
        let first_character = match private_key.wif().chars().next() {
            Some(c) => c,
            None => panic!("Error unwrapping first character of WIF"),
        };
        // Reference: https://en.bitcoin.it/wiki/Address#Address_map
        let is_valid_first_character = match (private_key.network(), private_key.compressed()) {
            (Network::Mainnet, false) => first_character == '5',
            (Network::Testnet, false) => first_character == '9',
            (Network::Mainnet, true) => first_character == 'L' || first_character == 'K',
            (Network::Testnet, true) => first_character == 'c',
            _ => false,
        };
        assert!(is_valid_first_character);
        let from_wif =
            PrivateKey::from_wif(private_key.wif()).expect("Error unwrapping private key from WIF");
        assert_eq!(from_wif.wif(), private_key.wif());
    }

    #[test]
    fn test_new_mainnet() {
        let private_key = PrivateKey::new(Network::Mainnet);
        test_new(private_key);
    }

    #[test]
    fn test_new_testnet() {
        let private_key = PrivateKey::new(Network::Testnet);
        test_new(private_key);
    }

    #[test]
    fn test_new_compressed_mainnet() {
        let private_key = PrivateKey::new_compressed(Network::Mainnet);
        test_new(private_key);
    }

    #[test]
    fn test_new_compressed_testnet() {
        let private_key = PrivateKey::new_compressed(Network::Testnet);
        test_new(private_key);
    }

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
            Network::Mainnet,
        )
    }

    #[test]
    fn test_testnet_to_wif() {
        test_to_wif(
            "37EE08B51CB5932276DB785C8E23CC0FDC99A2923C7ECA43A6D3FD26D94EBD44",
            "921YpFFoB1UN7tud1vne5hTrijX423MexQxYn6dmeHB25xT8c2s",
            Network::Testnet,
        )
    }
}

use keypair::KeyPair;
use utils::{to_checksum_address, to_hex_string};

use secp256k1::PublicKey;
use serde::Serialize;
use std::fmt;
use tiny_keccak::keccak256;

/// Represents an Ethereum Address
#[derive(Serialize, Debug)]
pub struct Address {
    pub address: String,
}

impl Address {
    /// Returns an Address given a KeyPair object
    pub fn from_key_pair(key_pair: &KeyPair) -> Address {
        let checksum_address = Address::from_public_key(&key_pair.to_public_key());

        Address {
            address: checksum_address,
        }
    }

    pub fn from_public_key(public_key: &PublicKey) -> String {
        let public_key = public_key.serialize_uncompressed();
        let hash = keccak256(&public_key[1..]);

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..]);

        let address = to_hex_string(&address_bytes).to_lowercase();

        to_checksum_address(&address)
    }

    pub fn address(&self) -> &str {
        &self.address
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    fn test_from_key_pair(secret_key_string: &str, expected_address: &str) {
        let secret_key = KeyPair::from_secret_key_string(secret_key_string);
        let key_pair = KeyPair::from_secret_key(secret_key);
        let address = Address::from_key_pair(&key_pair);
        assert_eq!(address.address().to_lowercase(), expected_address);
    }

    fn test_from_public_key(public_key_bytes: &[u8], expected_address: &str) {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_slice(&secp, public_key_bytes).expect("Failed to generate public key");
        let address = Address::from_public_key(&public_key);
        assert_eq!(address.to_lowercase(), expected_address);
    }

    #[test]
    fn test_functionality_from_key_pair() {
        test_from_key_pair(
            "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315",
            "0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
        )
    }

    #[test]
    fn test_functionality_from_public_key() {
        test_from_public_key(
            &[4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188],
            "0xbae08538d1c93051cda4ef7b37be72bd29124c58"
        )
    }
}

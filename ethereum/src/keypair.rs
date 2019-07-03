use utils::to_hex_string;

use rand::Rng;
use rand::rngs::OsRng;
use secp256k1::Secp256k1;
use secp256k1::{PublicKey, SecretKey};
use serde::Serialize;
use std::fmt;

/// Represents an Ethereum Key
#[derive(Serialize, Debug, Eq, PartialEq)]
pub struct KeyPair {
    /// The Secp256k1 SecretKey Object
    #[serde(skip_serializing)]
    secret_key: SecretKey,

    private_key: String,

    /// The Secp256k1 PublicKey Object
    #[serde(skip_serializing)]
    public_key: PublicKey,
}

impl KeyPair {
    /// Randomly generates a new private key
    pub fn new() -> KeyPair {
        let secret_key = KeyPair::generate_secret_key();
        let secp = Secp256k1::new();
        let private_key = KeyPair::private_key_from_secret_key(secret_key);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        KeyPair {
            secret_key,
            private_key,
            public_key,
        }
    }

    /// Randomly generate a Secp256k1 SecretKey
    fn generate_secret_key() -> SecretKey {
        let secp = Secp256k1::new();
        let mut rand_bytes = [0u8; 32];
        OsRng.try_fill(&mut rand_bytes)
            .expect("Error generating random bytes for private key");

        SecretKey::from_slice(&secp, &rand_bytes)
            .expect("Error creating secret key from byte slice")
    }

    /// Returns the Secp256k1 PublicKey generated from this KeyPair
    pub fn to_public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &self.secret_key)
    }

    /// Creates a KeyPair from a Secp256k1 SecretKey for the specified network
    pub fn from_secret_key(secret_key: SecretKey) -> KeyPair {
        let secp = Secp256k1::new();
        let private_key = KeyPair::private_key_from_secret_key(secret_key);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        KeyPair {
            secret_key,
            private_key,
            public_key,
        }
    }

    pub fn from_secret_key_string(secret_key_string: &str) -> SecretKey {
        let secp = Secp256k1::new();
        let secret_key_bytes = hex::decode(secret_key_string).expect("Error decoding string");

        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&secret_key_bytes[0..32]);

        SecretKey::from_slice(&secp, &secret_key)
            .expect("Error creating secret key from byte slice")
    }

    /// Generates the Ethereum private key from the Secp256k1 SecretKey
    pub fn private_key_from_secret_key(secret_key: SecretKey) -> String {
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&secret_key[..]);

        to_hex_string(&private_key_bytes).to_lowercase()
    }

    /// Returns an immutable reference to this KeyPair's Secp256k1 SecretKey
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Returns an immutable reference to this KeyPair's Ethereum private key
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// Returns an immutable reference to this KeyPair's Secp256k1 PublicKey
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_pair(key_pair: KeyPair) {
        let secp = Secp256k1::new();
        let expected_private_key = KeyPair::private_key_from_secret_key(*key_pair.secret_key());
        let expected_public_key = PublicKey::from_secret_key(&secp, key_pair.secret_key());
        assert_eq!(key_pair.private_key(), expected_private_key);
        assert_eq!(key_pair.public_key(), &expected_public_key);
    }

    fn test_to_public_key(secret_key_string: &str, expected_public_key: &str) {
        let secret_key = KeyPair::from_secret_key_string(secret_key_string);
        let key_pair = KeyPair::from_secret_key(secret_key);

        assert_eq!(key_pair.public_key().to_string(), expected_public_key);
    }

    fn test_from_secret_key(secret_key_string: &str) {
        test_key_pair(
            KeyPair::from_secret_key(
                KeyPair::from_secret_key_string(secret_key_string)
            )
        )
    }

    fn test_from_secret_key_string(secret_key_string: &str) {
        let secret_key = KeyPair::from_secret_key_string(secret_key_string);
        assert_eq!(secret_key.to_string(), secret_key_string);
    }

    #[test]
    fn test_new() {
        test_key_pair(KeyPair::new());
    }

    #[test]
    fn test_functionality_to_public_key() {
        test_to_public_key(
            "bca329365b086a46a47e0ccce37059c266d1d408476be222eb5bafbd07cce698",
            "038e25581f3acf823e3417ecd32a1d3479e292798a8d7538554c9039a51a659735"
        )
    }

    #[test]
    #[should_panic(expected = "Error decoding string")]
    fn test_invalid_secret_key_to_public_key() {
        test_to_public_key(
            "ca329365b086a46a47e0ccce37059c266d1d408476be222eb5bafbd07cce698",
            ""
        )
    }

    #[test]
    fn test_functionality_from_secret_key() {
        test_from_secret_key(
            "bca329365b086a46a47e0ccce37059c266d1d408476be222eb5bafbd07cce698"
        )
    }

    #[test]
    #[should_panic(expected = "Error decoding string")]
    fn test_invalid_secret_key_from_secret_key() {
        test_from_secret_key(
            "ca329365b086a46a47e0ccce37059c266d1d408476be222eb5bafbd07cce698"
        )
    }

    #[test]
    fn test_functionality_from_secret_key_string() {
        test_from_secret_key_string(
            "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315",
        )
    }

    #[test]
    #[should_panic(expected = "Error decoding string")]
    fn test_invalid_secret_key_from_secret_key_string() {
        test_from_secret_key_string(
            "ca329365b086a46a47e0ccce37059c266d1d408476be222eb5bafbd07cce698"
        )
    }

    #[test]
    fn test_private_key_from_secret_key() {
        let key_pair = KeyPair::new();
        let private_key = KeyPair::private_key_from_secret_key(*key_pair.secret_key());
        assert_eq!(key_pair.private_key(), private_key);
    }
}

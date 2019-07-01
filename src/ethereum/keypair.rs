extern crate hex;
extern crate rand;
extern crate secp256k1;

use std::fmt;

use ethereum::utils::to_hex_string;

use self::rand::thread_rng;
use self::rand::RngCore;
use self::secp256k1::Secp256k1;
use self::secp256k1::{PublicKey, SecretKey};

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
        let mut rng = thread_rng();
        rng.try_fill_bytes(&mut rand_bytes)
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

use crate::address::EthereumAddress;
use crate::format::EthereumFormat;
use crate::public_key::EthereumPublicKey;
use wagyu_model::{Address, AddressError, PrivateKey, PrivateKeyError, PublicKey};

use rand::Rng;
use secp256k1;
use std::{fmt, fmt::Display, str::FromStr};

/// Represents an Ethereum private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumPrivateKey(secp256k1::SecretKey);

impl PrivateKey for EthereumPrivateKey {
    type Address = EthereumAddress;
    type Format = EthereumFormat;
    type PublicKey = EthereumPublicKey;

    /// Returns a randomly-generated Ethereum private key.
    fn new<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError> {
        let random: [u8; 32] = rng.gen();
        Ok(Self(secp256k1::SecretKey::parse_slice(&random)?))
    }

    /// Returns the public key of the corresponding Ethereum private key.
    fn to_public_key(&self) -> Self::PublicKey {
        EthereumPublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Ethereum private key.
    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        EthereumAddress::from_private_key(self, _format)
    }
}

impl EthereumPrivateKey {
    /// Returns a private key given a secp256k1 secret key.
    pub fn from_secp256k1_secret_key(secret_key: &secp256k1::SecretKey) -> Self {
        Self(secret_key.clone())
    }

    /// Returns the secp256k1 secret key of the private key.
    pub fn to_secp256k1_secret_key(&self) -> secp256k1::SecretKey {
        self.0.clone()
    }
}

impl FromStr for EthereumPrivateKey {
    type Err = PrivateKeyError;

    fn from_str(private_key: &str) -> Result<Self, PrivateKeyError> {
        if private_key.len() != 64 {
            return Err(PrivateKeyError::InvalidCharacterLength(private_key.len()));
        }

        let secret_key = hex::decode(private_key)?;
        Ok(Self(secp256k1::SecretKey::parse_slice(&secret_key)?))
    }
}

impl Display for EthereumPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&self.0.serialize());
        write!(f, "{}", hex::encode(private_key).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_to_public_key(expected_public_key: &EthereumPublicKey, private_key: &EthereumPrivateKey) {
        let public_key = private_key.to_public_key();
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address(expected_address: &EthereumAddress, private_key: &EthereumPrivateKey) {
        let address = private_key.to_address(&EthereumFormat::Standard).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_secp256k1_secret_key(
        expected_private_key: &str,
        expected_public_key: &str,
        expected_address: &str,
        secret_key: secp256k1::SecretKey,
    ) {
        let private_key = EthereumPrivateKey::from_secp256k1_secret_key(&secret_key);
        assert_eq!(secret_key, private_key.0);
        assert_eq!(expected_private_key, private_key.to_string());
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(
            expected_address,
            private_key.to_address(&EthereumFormat::Standard).unwrap().to_string()
        );
    }

    fn test_from_str(
        expected_secret_key: &secp256k1::SecretKey,
        expected_public_key: &str,
        expected_address: &str,
        private_key: &str,
    ) {
        let private_key = EthereumPrivateKey::from_str(private_key).unwrap();
        assert_eq!(*expected_secret_key, private_key.0);
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(
            expected_address,
            private_key.to_address(&EthereumFormat::Standard).unwrap().to_string()
        );
    }

    fn test_to_str(expected_private_key: &str, private_key: &EthereumPrivateKey) {
        assert_eq!(expected_private_key, private_key.to_string());
    }

    mod checksum_address {
        use super::*;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "8279d7c0ae2c3266b557845d50ede43e22a7e60408b7c90ee279b8848dbac771",
                "9e984180d8e431b31f51d605639d6eaa447a36189834c10238203aff6c100090738d6a8d293cbc3461d0c17b2ee966364076e37c2ce186acfa6b44d426ac079c",
                "0xA069665F5E31B932b7F5E50FF552A261a694b1DB"
            ),
            (
                "444d0c9a7cb33240a0799a0edc0d89a96b20abf10f91b33d7f5812b49d4f0d95",
                "c86d6b2d319e8267a5dac084aed74c28754b9ea18291ed36d5f1dcf7f9debaef2b25a48d2ae89add88c9797f6f5553235a13db23deac3c8597d52593c056aac3",
                "0xdeA0f51325b69323f0C73e2f81A0a389d55Bbca5"
            ),
            (
                "40d4098958b22c19e866f0761f5d589fcc088b78f4e881bfda7ebee7df044bdd",
                "d1b1ab9c694894950da166520af3081c1f169c7306f2ed8ce507928832aa0429b35476084efd325439f2016f174b3e0243df7f40f92111aaa191c82dd94bf8d7",
                "0x36D0E703Aa4733AFB3CDFC000D66BE65d14fFfc8"
            ),
            (
                "f56ebd9b96ddbd8faf320ae8af2b49aeff4b54dc8867a6c39092fe1aa7434b7e",
                "8d270aba1ed09d353d7c8c892593b628499eb1d714fbaabd9938e43cbb847cefa0435b29f1541ab397b1482c028f95b83f56603f5183f432ae862bcbccf13e04",
                "0x337b22d054eed94C6c0711B3b0bd7DDaE23e5DC5"
            ),
            (
                "ab95d2466269a48e96f92fe36dfcecf67b4a6f9394de9ec7314dd584426a638c",
                "8269368cad7ce74a530954da01db01e4e62f17625869ad10eabf3a261b5ab6d396b0e1e307455d2ae0f63032b748f909fcea2fbaf36a76536cb298ce343d882c",
                "0x020D80b9B932eE57eFDD2eD35cb4d409554013ba"
            )
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = EthereumPublicKey::from_str(public_key).unwrap();
                let private_key = EthereumPrivateKey::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = EthereumAddress::from_str(address).unwrap();
                let private_key = EthereumPrivateKey::from_str(&private_key).unwrap();
                test_to_address(&address, &private_key);
            });
        }

        #[test]
        fn from_secp256k1_secret_key() {
            KEYPAIRS
                .iter()
                .for_each(|(expected_private_key, expected_public_key, expected_address)| {
                    let private_key = EthereumPrivateKey::from_str(&expected_private_key).unwrap();
                    test_from_secp256k1_secret_key(
                        expected_private_key,
                        expected_public_key,
                        expected_address,
                        private_key.0,
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = EthereumPrivateKey::from_str(&private_key).unwrap();
                    test_from_str(
                        &expected_private_key.0,
                        expected_public_key,
                        expected_address,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = EthereumPrivateKey::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }
    }

    #[test]
    fn test_checksum_address_invalid() {
        // Invalid private key length

        let private_key = "8";
        assert!(EthereumPrivateKey::from_str(private_key).is_err());

        let private_key = "8279d7c0ae2c3266b557845d50ede43";
        assert!(EthereumPrivateKey::from_str(private_key).is_err());

        let private_key = "8279d7c0ae2c3266b557845d50ede43e22a7e60408b7c90ee279b8848dbac77";
        assert!(EthereumPrivateKey::from_str(private_key).is_err());

        let private_key =
            "8279d7c0ae2c3266b557845d50ede43e22a7e60408b7c90ee279b8848dbac7718279d7c0ae2c3266b557845d50ede43";
        assert!(EthereumPrivateKey::from_str(private_key).is_err());

        let private_key = "8279d7c0ae2c3266b557845d50ede43e22a7e60408b7c90ee279b8848dbac7718279d7c0ae2c3266b557845d50ede43e22a7e60408b7c90ee279b8848dbac771";
        assert!(EthereumPrivateKey::from_str(private_key).is_err());
    }
}

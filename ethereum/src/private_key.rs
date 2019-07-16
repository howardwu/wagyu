use crate::address::EthereumAddress;
use crate::public_key::EthereumPublicKey;
use wagu_model::{
    //    bytes::{FromBytes, ToBytes},
    Address,
    PrivateKey,
    PublicKey,
};

use rand::rngs::OsRng;
use rand::Rng;
use secp256k1;
use secp256k1::Secp256k1;
//use std::io::{Read, Result as IoResult, Write};
use std::{fmt, fmt::Display};
use std::marker::PhantomData;
use std::str::FromStr;

/// Represents an Ethereum private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EthereumPrivateKey {
    /// The ECDSA private key
    pub secret_key: secp256k1::SecretKey,
}

impl PrivateKey for EthereumPrivateKey {
    type Address = EthereumAddress;
    type Format = PhantomData<u8>;
    type Network = PhantomData<u8>;
    type PublicKey = EthereumPublicKey;

    /// Returns a randomly-generated Ethereum private key.
    fn new(_network: &Self::Network) -> Self {
        Self::build()
    }

    /// Returns the public key of the corresponding Ethereum private key.
    fn to_public_key(&self) -> Self::PublicKey {
        EthereumPublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Ethereum private key.
    fn to_address(&self, _: &Self::Format) -> Self::Address {
        EthereumAddress::from_private_key(self, &PhantomData)
    }
}

impl EthereumPrivateKey {
    /// Returns either a Ethereum private key struct or errors.
    pub fn from(private_key: &str) -> Result<Self, &'static str> {
        if private_key.len() != 64 {
            return Err("invalid length")
        }
        let secret_key = hex::decode(private_key).expect("invalid hex string");
        Ok(Self {
            secret_key: secp256k1::SecretKey::from_slice(&Secp256k1::new(), &secret_key)
                .expect("Error converting byte slice to secret key")
        })
    }

    /// Returns a private key given a secp256k1 secret key
    pub fn from_secret_key(secret_key: secp256k1::SecretKey) -> Self {
        Self { secret_key }
    }

    /// Returns a randomly-generated Ethereum private key.
    fn build() -> Self {
        let secret_key = Self::random_secret_key();
        Self { secret_key }
    }

    /// Returns a randomly-generated secp256k1 secret key.
    fn random_secret_key() -> secp256k1::SecretKey {
        let mut random = [0u8; 32];
        OsRng.try_fill(&mut random).expect("Error generating random bytes for private key");
        secp256k1::SecretKey::from_slice(&Secp256k1::new(), &random)
            .expect("Error creating secret key from byte slice")
    }
}

impl Default for EthereumPrivateKey {
    /// Returns a randomly-generated Ethereum private key.
    fn default() -> Self {
        Self::new(&PhantomData)
    }
}

//impl FromBytes for EthereumPrivateKey {
//    #[inline]
//    fn read<R: Read>(reader: R) -> IoResult<Self> {
//        let mut f = reader;
//        let mut buffer = Vec::new();
//        f.read_to_end(&mut buffer)?;
//
//        Self::from_str(buffer.to_base58().as_str())?
//    }
//}
//
//impl ToBytes for EthereumPrivateKey {
//    #[inline]
//    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
//        let buffer = self.wif.as_str().from_base58()?.as_slice();
//        buffer.write(writer)
//    }
//}

impl FromStr for EthereumPrivateKey {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, &'static str> {
        Self::from(s)
    }
}

impl Display for EthereumPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&self.secret_key[..]);
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
        let address = private_key.to_address(&PhantomData);
        assert_eq!(*expected_address, address);
    }

    fn test_from(
        expected_secret_key: &secp256k1::SecretKey,
        expected_public_key: &str,
        expected_address: &str,
        private_key: &str
    ) {
        let private_key = EthereumPrivateKey::from(private_key).unwrap();
        assert_eq!(*expected_secret_key, private_key.secret_key);
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(expected_address, private_key.to_address(&PhantomData).to_string());
    }

    fn test_from_secret_key(
        expected_private_key: &str,
        expected_public_key: &str,
        expected_address: &str,
        secret_key: secp256k1::SecretKey,
    ) {
        let private_key = EthereumPrivateKey::from_secret_key(secret_key);
        assert_eq!(secret_key, private_key.secret_key);
        assert_eq!(expected_private_key, private_key.to_string());
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(expected_address, private_key.to_address(&PhantomData).to_string());
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
        fn from() {
            KEYPAIRS.iter().for_each(|(private_key, expected_public_key, expected_address)| {
                let expected_private_key = EthereumPrivateKey::from_str(&private_key).unwrap();
                test_from(
                    &expected_private_key.secret_key,
                    expected_public_key,
                    expected_address,
                    &private_key);
            });
        }

        #[test]
        fn from_secret_key() {
            KEYPAIRS.iter().for_each(|(expected_private_key, expected_public_key, expected_address)| {
                let private_key = EthereumPrivateKey::from_str(&expected_private_key).unwrap();
                test_from_secret_key(
                    expected_private_key,
                    expected_public_key,
                    expected_address,
                    private_key.secret_key);
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

        let private_key = "8279d7c0ae2c3266b557845d50ede43e22a7e60408b7c90ee279b8848dbac7718279d7c0ae2c3266b557845d50ede43";
        assert!(EthereumPrivateKey::from_str(private_key).is_err());

        let private_key = "8279d7c0ae2c3266b557845d50ede43e22a7e60408b7c90ee279b8848dbac7718279d7c0ae2c3266b557845d50ede43e22a7e60408b7c90ee279b8848dbac771";
        assert!(EthereumPrivateKey::from_str(private_key).is_err());

    }
}
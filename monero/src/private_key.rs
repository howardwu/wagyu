use crate::address::{Format, MoneroAddress};
use crate::network::Network;
use crate::public_key::MoneroPublicKey;
use wagu_model::{Address, PrivateKey, PrivateKeyError, PublicKey};

use curve25519_dalek::{scalar::Scalar};
use hex;
use rand::Rng;
use rand::rngs::OsRng;
use std::{fmt, fmt::Display};
use std::str::FromStr;
use tiny_keccak::keccak256;

/// Represents a Monero private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MoneroPrivateKey {
    /// The private spending key
    pub spend_key: [u8; 32],
    /// The private viewing key
    pub view_key: [u8; 32],
    /// The network of the private key
    pub network: Network,
}

impl PrivateKey for MoneroPrivateKey {
    type Address = MoneroAddress;
    type Format = Format;
    type Network = Network;
    type PublicKey = MoneroPublicKey;

    /// Returns a randomly-generated Monero private key.
    fn new(network: &Self::Network) -> Result<Self, PrivateKeyError> {
        let mut random = [0u8; 32];
        OsRng.try_fill(&mut random)?;
        Self::from_seed(hex::encode(random).as_str(), network)
    }

    /// Returns the public key of the corresponding Monero private key.
    fn to_public_key(&self) -> Self::PublicKey {
        MoneroPublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Monero private key.
    fn to_address(&self, format: &Self::Format) -> Self::Address {
        MoneroAddress::from_private_key(self, format)
    }
}

impl MoneroPrivateKey {
    /// Returns a private key given seed bytes.
    pub fn from_seed(seed: &str, network: &Network) -> Result<Self, PrivateKeyError> {
        let seed = hex::decode(seed)?;
        if seed.len() != 32 {
            return Err(PrivateKeyError::InvalidByteLength(seed.len()))
        }

        let mut s = [0u8; 32];
        s.copy_from_slice(seed.as_slice());

        let spend_key = Scalar::from_bytes_mod_order(s).to_bytes();
        Ok(Self {
            spend_key,
            view_key: Scalar::from_bytes_mod_order(keccak256(&spend_key)).to_bytes(),
            network: *network
        })
    }

    /// Returns a private key given a private spend key.
    pub fn from_private_spend_key(
        private_spend_key: &str,
        network: &Network
    ) -> Result<Self, PrivateKeyError> {
        let key = hex::decode(private_spend_key)?;
        if key.len() != 32 {
            return Err(PrivateKeyError::InvalidByteLength(key.len()))
        }

        let mut spend_key = [0u8; 32];
        spend_key.copy_from_slice(key.as_slice());

        Ok(Self {
            spend_key,
            view_key: Scalar::from_bytes_mod_order(keccak256(&spend_key)).to_bytes(),
            network: *network
        })
    }
}

impl FromStr for MoneroPrivateKey {
    type Err = PrivateKeyError;
    // TODO (howardwu): Add parsing of mainnet or testnet as an option.
    fn from_str(seed: &str) -> Result<Self, PrivateKeyError> {
        Self::from_seed(seed, &Network::Mainnet)
    }
}

impl Display for MoneroPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(")?;
        for byte in &self.spend_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ", ")?;
        for byte in &self.view_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_to_public_key(expected_public_key: &MoneroPublicKey, private_key: &MoneroPrivateKey) {
        let public_key = private_key.to_public_key();
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address(expected_address: &MoneroAddress, expected_format: &Format, private_key: &MoneroPrivateKey) {
        let address = private_key.to_address(expected_format);
        assert_eq!(*expected_address, address);
    }

    fn test_from_seed(
        expected_private_spend_key: &str,
        expected_private_view_key: &str,
        expected_address: &str,
        expected_format: &Format,
        seed: &str,
        network: &Network
    ) {
        let private_key = MoneroPrivateKey::from_seed(seed, network).unwrap();
        assert_eq!(expected_private_spend_key, hex::encode(private_key.spend_key));
        assert_eq!(expected_private_view_key, hex::encode(private_key.view_key));
        assert_eq!(*network, private_key.network);
        assert_eq!(expected_address, private_key.to_address(expected_format).to_string());
    }

    fn test_from_private_spend_key(
        expected_private_view_key: &str,
        expected_address: &str,
        expected_format: &Format,
        private_spend_key: &str,
        network: &Network,
    ) {
        let private_key = MoneroPrivateKey::from_private_spend_key(private_spend_key, network).unwrap();
        assert_eq!(private_spend_key, hex::encode(private_key.spend_key));
        assert_eq!(expected_private_view_key, hex::encode(private_key.view_key));
        assert_eq!(*network, private_key.network);
        assert_eq!(expected_address, private_key.to_address(expected_format).to_string());
    }

    fn test_to_str(
        expected_private_spend_key: &str,
        expected_private_view_key: &str,
        private_key: &MoneroPrivateKey
    ) {
        assert_eq!(format!("({}, {})", expected_private_spend_key, expected_private_view_key), private_key.to_string());
    }

    mod standard_mainnet {
        use super::*;

        // (seed, (private_spend_key, private_view_key), (public_spend_key, public_view_key), address)
        const KEYPAIRS: [(&str, (&str, &str), (&str, &str), &str); 5] = [
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                ("3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600", "5177c436f032666c572df97ab591cc6ac2da96ab6818a2f38d72b430aebbdc0a"),
                ("b9c5610a07f4344b27625155614fb1341dd0392c68482f101b820bc1e2b908e5", "0df7c88054ae3c5f75c364257d064f42d660e6ea1184bd2a3af0d7455cb4e9ee"),
                "48fRSJiQSp3Da61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xTungkh5"
            ),
            (
                "a90aaafd9d8112848ca44b3230fbda22974b0ba1b0e74870bda8825d6ff60b06",
                ("a90aaafd9d8112848ca44b3230fbda22974b0ba1b0e74870bda8825d6ff60b06", "498a9d7cc43b05eee500a60901c1007990ad5c0e637d72d5f6f5dfd86f50ec09"),
                ("07ab31ccf46bda1d9dee0344b03cf689fb1f9302bd1f13fe52048e73b258f1e1", "cec2f7e6079ff911e6a4cc00942f18fa8abb0d247b27c41a785035136ff7412d"),
                "41uxs7goiMo5xKdNQosRUhQ5b7EyyY6SWjYE8D1BLuoWemcoD3wWkpY3zfNpcgPtNjiua5wPQoB395Rnvy159VnY67GHR9b"
            ),
            (
                "cff04d7e8db3f7910f6044a61e079a6e006b878f1e31596441951148be3f030c",
                ("cff04d7e8db3f7910f6044a61e079a6e006b878f1e31596441951148be3f030c", "539e8ee06b61cb4a6ee3875b18b10d8ce113c93d3b766af7d7ca24dc2b3f3c01"),
                ("70dddd449b5011e08876d307a76bf2d6bbd04b2cff4f7e3e5fde3d352065b5a3", "087fd0571b27542ff94e3cd88dfacf1f5c6d5736feec0a8e36e038107eed0741"),
                "45uBYxmi472eZFce75VAobcvBkZW1jGhbBS7RBWSSp9rUGdKm6gYc5R92QaGLesxNJ6FF167AWws7Qnf8aayDvkN8Q5CqEU"
            ),
            (
                "3de1ab3ee61116692a18e2cbd0f4be70e19200262b9426ef2ea3c990d0068700",
                ("3de1ab3ee61116692a18e2cbd0f4be70e19200262b9426ef2ea3c990d0068700", "394c84948bd577a8cb1dffa4cbccb51f65ac5439f8e256b0a0374b320bc99802"),
                ("72d2c60260247ef57c875c1fbd51352368731d38f32cb050fd2ab27b9cb54d54", "891a9b16a83efa53f56bac0412fe2cdfdfbfe6d8fbaf879cbc8fb28ec3a28553"),
                "45yUzNd6Kzdi4XWQCPhauA6vW7nXkwDNXEYhFwy7c2NGF96rFUscKE9F3WFW3i6ixTeSrnpfMxgdCTDYP4sCcBkxANMA62p"
            ),
            (
                "7dc2f3340b8f41b6f5166235011d1fa58e7f2d32d761a56dc3e618255692c704",
                ("7dc2f3340b8f41b6f5166235011d1fa58e7f2d32d761a56dc3e618255692c704", "5a224a898a42d48025efccfb14c2062610ec95ddfe02c764e6ababe1ed44780d"),
                ("ccfc5403e256475e5824310864cff02da9badeeeae09c7a78baf920f89332b20", "c1b9ecd218547d81c3a15a0c0c6b02f0a56def8748f39eef054397a9df27f5c9"),
                "49PevuALZP4GnFxcmJLwt38dzKtg35WSiV2QMYfcQ6KU6UnKmkcUngCNhskr4Pu4ZwhFa3NY1jyRXgyoLPWBK4gcPmyURJg"
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(seed, _, (public_spend_key, public_view_key), _)| {
                let public_key = MoneroPublicKey::from(public_spend_key, public_view_key).unwrap();
                let private_key = MoneroPrivateKey::from_seed(seed, &Network::Mainnet).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(seed, _, _, address)| {
                let address = MoneroAddress::from_str(address).unwrap();
                let private_key = MoneroPrivateKey::from_seed(seed, &Network::Mainnet).unwrap();
                test_to_address(&address, &Format::Standard, &private_key);
            });
        }

        #[test]
        fn from_seed() {
            KEYPAIRS.iter().for_each(|(seed, (private_spend_key, private_view_key), _, address)| {
                test_from_seed(
                    private_spend_key,
                    private_view_key,
                    address,
                    &Format::Standard,
                    seed,
                    &Network::Mainnet);
            });
        }

        #[test]
        fn from_private_spend_key() {
            KEYPAIRS.iter().for_each(|(_, (private_spend_key, private_view_key), _, address)| {
                test_from_private_spend_key(
                    private_view_key,
                    address,
                    &Format::Standard,
                    private_spend_key,
                    &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(seed, (private_spend_key, private_view_key), _, _)| {
                let private_key = MoneroPrivateKey::from_seed(seed, &Network::Mainnet).unwrap();
                test_to_str(private_spend_key, private_view_key, &private_key);
            });
        }
    }
}

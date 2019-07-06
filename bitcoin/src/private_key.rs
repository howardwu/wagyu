use crate::address::{BitcoinAddress, Format};
use model::{Address, PrivateKey, PublicKey, crypto::checksum};
use crate::network::Network;
use crate::public_key::BitcoinPublicKey;

use base58::{FromBase58, ToBase58};
use rand::Rng;
use rand::rngs::OsRng;
use secp256k1;
use secp256k1::Secp256k1;
use std::{fmt, fmt::Display};
//use std::io::{Write};
use std::str::FromStr;

/// Represents a Bitcoin private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitcoinPrivateKey {
    /// The ECDSA private key
    pub secret_key: secp256k1::SecretKey,
    /// The Wallet Import Format (WIF) string encoding
    pub wif: String,
    /// The network of the private key
    pub network: Network,
    /// If true, the private key is serialized in compressed form
    pub compressed: bool,
}

impl PrivateKey for BitcoinPrivateKey {
    type Address = BitcoinAddress;
    type Format = Format;
    type Network = Network;
    type PublicKey = BitcoinPublicKey;

    /// Returns a randomly-generated compressed Bitcoin private key.
    fn new(network: &Self::Network) -> Self {
        Self::build(network, true)
    }

    /// Returns the public key of the corresponding Bitcoin private key.
    fn to_public_key(&self) -> Self::PublicKey {
        BitcoinPublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Bitcoin private key.
    fn to_address(&self, format: &Self::Format) -> Self::Address {
        BitcoinAddress::from_private_key(self, format)
    }
}

impl BitcoinPrivateKey {

    /// Returns a private key given a secp256k1 secret key
    pub fn from_secret_key(secret_key: secp256k1::SecretKey, network: &Network) -> Self {
        let compressed = secret_key.len() == 65;
        let wif = Self::secret_key_to_wif(&secret_key, &network, compressed);
        Self { secret_key, wif, network: *network, compressed }
    }

    /// Returns either a Bitcoin private key struct or errors.
    pub fn from_wif(wif: &str) -> Result<Self, &'static str> {
        let data = wif.from_base58().expect("Error decoding base58 wif");
        let len = data.len();

        let expected = &data[len - 4..len];
        let checksum = &checksum(&data[0..len - 4])[0..4];

        match *expected == *checksum {
            true => Ok(Self {
                network: Network::from_wif_prefix(data[0])?,
                wif: wif.into(),
                secret_key: secp256k1::SecretKey::from_slice(&Secp256k1::without_caps(), &data[1..33])
                    .expect("Error creating secret key from slice"),
                compressed: len == 38,
            }),
            false => Err("Invalid wif")
        }
    }

    /// Returns a randomly-generated Bitcoin private key.
    fn build(network: &Network, compressed: bool) -> Self {
        let secret_key = Self::random_secret_key();
        let wif = Self::secret_key_to_wif(&secret_key, network, compressed);
        Self { secret_key, wif, network: *network, compressed }
    }

    /// Returns a randomly-generated secp256k1 secret key.
    fn random_secret_key() -> secp256k1::SecretKey {
        let mut random = [0u8; 32];
        OsRng.try_fill(&mut random).expect("Error generating random bytes for private key");
        secp256k1::SecretKey::from_slice(&Secp256k1::new(), &random)
            .expect("Error creating secret key from byte slice")
    }

    /// Returns a WIF string given a secp256k1 secret key.
    fn secret_key_to_wif(secret_key: &secp256k1::SecretKey, network: &Network, compressed: bool) -> String {
        let mut wif = [0u8; 38];
        wif[0] = network.to_wif_prefix();
        wif[1..33].copy_from_slice(&secret_key[..]);

        if compressed {
            wif[33] = 0x01;
            let sum = &checksum(&wif[0..34])[0..4];
            wif[34..].copy_from_slice(sum);
            wif.to_base58()
        } else {
            let sum = &checksum(&wif[0..33])[0..4];
            wif[33..37].copy_from_slice(sum);
            wif[..37].to_base58()
        }
    }
}

impl Default for BitcoinPrivateKey {
    /// Returns a randomly-generated mainnet Bitcoin private key.
    fn default() -> Self {
        Self::new(&Network::Mainnet)
    }
}

//impl FromBytes for BitcoinPrivateKey {
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
//impl ToBytes for BitcoinPrivateKey {
//    #[inline]
//    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
//        let buffer = self.wif.as_str().from_base58()?.as_slice();
//        buffer.write(writer)
//    }
//}

impl FromStr for BitcoinPrivateKey {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, &'static str> {
        Self::from_wif(s)
    }
}

impl Display for BitcoinPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.wif)
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::*;
    use secp256k1::{ Message, SecretKey };

    fn get_secret_key_from_string(secret_key_string: &str) -> SecretKey{
        let secp = Secp256k1::without_caps();
        let secret_key_as_bytes =
            hex::decode(secret_key_string).expect("Error decoding secret key from hex string");

        SecretKey::from_slice(&secp, &secret_key_as_bytes)
            .expect("Error deriving secret key from hex string")
    }

    fn test_to_public_key(secret_key_string: &str, expected_public_key: &str, network: &Network) {
        let secret_key = get_secret_key_from_string(secret_key_string);
        let private_key = BitcoinPrivateKey::from_secret_key(secret_key, network);
        let public_key = private_key.to_public_key();
        assert_eq!(public_key.to_string(), expected_public_key);
    }

    fn test_from_secret_key(secret_key_string: &str, expected_wif: &str, network: &Network) {
        let secret_key = get_secret_key_from_string(secret_key_string);
        let private_key = BitcoinPrivateKey::from_secret_key(secret_key, network);
        assert_eq!(private_key.wif, expected_wif);
    }

    fn test_from_wif(wif: &str, secret_key_string: &str) {
        let private_key = BitcoinPrivateKey::from_wif(wif).expect("Error deriving private key from wif");
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
        let private_key = BitcoinPrivateKey::from_secret_key(secret_key, network);
        assert_eq!(private_key.secret_key, secret_key);
        assert_eq!(private_key.wif, wif);
    }

    fn test_new(private_key: BitcoinPrivateKey) {
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
        };
        assert!(is_valid_first_character);
        let from_wif =
            BitcoinPrivateKey::from_wif(private_key.wif.as_str()).expect("Error unwrapping private key from WIF");
        assert_eq!(from_wif.wif, private_key.wif);
    }

    #[test]
    fn test_new_mainnet() {
        let private_key = BitcoinPrivateKey::new(&Network::Mainnet);
        test_new(private_key);
    }

    #[test]
    fn test_new_testnet() {
        let private_key = BitcoinPrivateKey::new(&Network::Testnet);
        test_new(private_key);
    }

    #[test]
    fn test_new_compressed_mainnet() {
        let private_key = BitcoinPrivateKey::new(&Network::Mainnet);
        test_new(private_key);
    }

    #[test]
    fn test_new_compressed_testnet() {
        let private_key = BitcoinPrivateKey::new(&Network::Testnet);
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
    #[should_panic(expected = "Error decoding base58 wif")]
    fn test_invalid_characters_from_wif() {
        test_from_wif(
            "!@#$%^&*",
            ""
        )
    }

    #[test]
    #[should_panic(expected = "Error deriving private key from wif")]
    fn test_invalid_wif_from_wif() {
        test_from_wif(
            "3HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
            ""
        )
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

    #[test]
    fn test_mainnet_get_public_key() {
        test_to_public_key(
            "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
            "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a",
            &Network::Mainnet
        )
    }

    #[test]
    fn test_testnet_get_public_key() {
        test_to_public_key(
            "c36fcf36a3a80e54e046313e8d4eff4a62addc309702cee016706e3280972355",
            "041db76245e286074dc2e7f0dd7227d6ea64a26b5a655b73477db8152ea7d5b71cd645fe3aeabd7b709850870d0bfd88e72f8152a4006c73183fa3ec2dc235890c",
            &Network::Testnet
        )
    }

    #[test]
    fn test_to_public_key_secp() {
        let secp = Secp256k1::new();
        let private_key = BitcoinPrivateKey::new(&Network::Mainnet);
        let public_key = private_key.to_public_key().public_key;
        let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");

        let sig = secp.sign(&message, &private_key.secret_key);
        assert!(secp.verify(&message, &sig, &public_key).is_ok());
    }

    #[test]
    fn test_mainnet_from_secret_key() {
        test_from_secret_key(
            "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
            &Network::Mainnet
        )
    }

    #[test]
    fn test_testnet_from_secret_key() {
        test_from_secret_key(
            "37EE08B51CB5932276DB785C8E23CC0FDC99A2923C7ECA43A6D3FD26D94EBD44",
            "921YpFFoB1UN7tud1vne5hTrijX423MexQxYn6dmeHB25xT8c2s",
            &Network::Testnet
        )
    }

    #[test]
    #[should_panic(expected = "Error decoding secret key from hex string")]
    fn test_invalid_characters_from_secret_key() {
        test_from_secret_key(
            "!@#$%^&*",
            "",
            &Network::Mainnet
        )
    }

    #[test]
    #[should_panic(expected = "Error decoding secret key from hex string")]
    fn test_invalid_secret_key_from_secret_key() {
        test_from_secret_key(
            "C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
            "",
            &Network::Mainnet
        )
    }
}

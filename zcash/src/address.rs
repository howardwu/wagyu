use crate::network::Network;
use crate::private_key::ZcashPrivateKey;
use crate::public_key::ZcashPublicKey;
use model::{Address, crypto::{checksum, hash160}, PrivateKey};

use base58::{FromBase58, ToBase58};
use serde::Serialize;
use std::fmt;
use std::str::FromStr;

/// Represents the format of a Zcash address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Pay-to-Pubkey Hash, transparent address beginning with "t1" or "tm"
    P2PKH,
    /// Pay-to-Script Hash, transparent address beginning with "t3" or "t2"
    P2SH,
    /// Sprout shielded address beginning with "zc" or "zt"
    Sprout,
}

impl Format {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix(&self, network: &Network) -> [u8; 2] {
        match network {
            Network::Mainnet => match self {
                Format::P2PKH => [0x1C, 0xB8],
                Format::P2SH => [0x1C, 0xBD],
                Format::Sprout => [0x16, 0x9A]
            },
            Network::Testnet => match self {
                Format::P2PKH => [0x1D, 0x25],
                Format::P2SH => [0x1C, 0xBA],
                Format::Sprout => [0x16, 0xB6]
            },
        }
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: &[u8; 2]) -> Result<Self, &'static str> {
        match prefix {
            [0x1C, 0xB8] | [0x1D, 0x25] => Ok(Format::P2PKH),
            [0x1C, 0xBD] | [0x1C, 0xBA] => Ok(Format::P2SH),
            [0x16, 0x9A] | [0x16, 0xB6] => Ok(Format::Sprout),
            _ => return Err("invalid address prefix")
        }
    }
}

/// Represents a Zcash t-address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashAddress {
    /// The Zcash address
    pub address: String,
    /// The format of the address
    pub format: Format,
    /// The network on which this address is usable
    pub network: Network,
}

impl Address for ZcashAddress {
    type Format = Format;
    type Network = Network;
    type PrivateKey = ZcashPrivateKey;
    type PublicKey = ZcashPublicKey;

    /// Returns the address corresponding to the given Zcash private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Self {
        let public_key = private_key.to_public_key();
        match format {
            Format::P2PKH => Self::p2pkh(&public_key, &private_key.network),
            Format::P2SH => Self::p2sh( &private_key.network),
            Format::Sprout => Self::shielded(&public_key, &private_key.network),
        }
    }

    /// Returns the address corresponding to the given Zcash public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
        network: &Self::Network
    ) -> Self {
        match format {
            Format::P2PKH => Self::p2pkh(public_key, network),
            Format::P2SH => Self::p2sh(network),
            Format::Sprout => Self::shielded(public_key, network),
        }
    }
}

impl ZcashAddress {
    /// Returns a transparent address from a given Zcash public key.
    pub fn p2pkh(public_key: &ZcashPublicKey, network: &Network) -> Self {
        let public_key = match public_key.compressed {
            true => public_key.public_key.serialize().to_vec(),
            false => public_key.public_key.serialize_uncompressed().to_vec()
        };

        let mut address = [0u8; 26];
        address[0..2].copy_from_slice(&Format::P2PKH.to_address_prefix(network));
        address[2..22].copy_from_slice(&hash160(&public_key));

        let sum = &checksum(&address[0..22])[0..4];
        address[22..26].copy_from_slice(sum);

        Self {
            address: address.to_base58(),
            format: Format::P2PKH,
            network: network.clone(),
        }
    }

    /// Returns a P2SH address.
    // TODO (howardwu): implement address scheme
    pub fn p2sh(_network: &Network) -> Self {
        unimplemented!("p2sh addresses are unimplemented");
    }

    /// Returns a shielded address from a given Zcash public key.
    // TODO (howardwu): implement address scheme
    pub fn shielded(_public_key: &ZcashPublicKey, _network: &Network) -> Self {
        unimplemented!("shielded addresses are unimplemented");
    }
}

impl FromStr for ZcashAddress {
    type Err = &'static str;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() > 50 {
            return Err("invalid character length");
        }

        let data = address.from_base58().expect("invalid base58 format");
        if data.len() != 26 {
            return Err("invalid byte length");
        }

        let mut prefix = [0u8; 2];
        prefix.copy_from_slice(&data[0..2]);

        let format = Format::from_address_prefix(&prefix)?;
        let network = Network::from_address_prefix(&prefix)?;

        Ok(Self { address: address.into(), format, network })
    }
}

impl fmt::Display for ZcashAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::public_key::PublicKey;

    fn test_from_private_key(
        expected_address: &str,
        private_key: &ZcashPrivateKey,
        format: &Format,
    ) {
        let address = ZcashAddress::from_private_key(private_key, format);
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key(
        expected_address: &str,
        public_key: &ZcashPublicKey,
        format: &Format,
        network: &Network,
    ) {
        let address = ZcashAddress::from_public_key(public_key, format, network);
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str(expected_address: &str, expected_format: &Format, expected_network: &Network) {
        let address = ZcashAddress::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
        assert_eq!(*expected_network, address.network);
    }

    fn test_to_str(expected_address: &str, address: &ZcashAddress) {
        assert_eq!(expected_address, address.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "KxYzZuBPkE3rnEEGCdsB6dCzxN1D4xoY5ogKoxbdUdkxbRzvgbij",
                "t1MoMR1XdnPqLBWf5XkchWTkGNrveYLCaiM"
            ),
            (
                "KyuC6qNxMiuPEF4wp6eLsJuczLKqHsdsdSx5c3a1boY81mpahuR6",
                "t1cnUnLfXZsb7gM7h9zD6QXm1wEDi4NxvTi"
            ),
            (
                "KxNLHESzCRfzTfF9KGsF68QtV9fT9qFRAH5UKpVUdMvc4TTcBmhJ",
                "t1VenYPx8HCiq6YFbuh1HbLGwtDZxQ5hQCr"
            ),
            (
                "L5XgV3xUnqcqJyJm3JZmtZyj5i8FmUbuj9LCz9n3FA87Ertn2Qod",
                "t1U9A7fh864FCzePbrXeUdjvuMfuCYKijbr"
            ),
            (
                "L17dC6ZcGfKu84FGastka34sB8yV9fzgbKJaafVWi4zKs6ETnF2x",
                "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH, &Network::Mainnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2PKH, &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "5HwduFgmNrhcgXpD7TH2ZbqBzfET3FzRLwapJdZYUNyxPz6MYQU",
                "t1gxf6ykX23Ha3Bf1bKhjJzdxtCPratotJK"
            ),
            (
                "5KFcAbDaap4ZqF1pCTq6rKWU6bUZg3bnqHJYaCEh6NUu8aVTszm",
                "t1QnYYpiVpmwHPtrRSJqypnDxG77284NUtj"
            ),
            (
                "5KXotG2j5THVbdf2Uf87HPZFRNaVqZYrrBVnZzczyDVza39q94f",
                "t1XEXEt3KeEYzycPTzn3invLivktYifWuXJ"
            ),
            (
                "5KPN7LeX6uzBpTYdC28xjgHkN5XbCKZVJiu9QquSCEFJcD7ndnv",
                "t1VxdN6a4T6RiSwgkNURkHhjLuoThvZWaHC"
            ),
            (
                "5JewwWXmgcdk9P762F3Pdr8RBcWfWVAAotq9mjSNBcEvZsQBJ32",
                "t1XraTEGoX5QjnhAqDs9F8AqvDEh4zohhUQ"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH, &Network::Mainnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2PKH, &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cPFtCjL9EXtgZQJSD13NMn1p3mhoXXHSqF9kXEX97XNPsz1b97ti",
                "tmW3honY9Uz7WhSJPwRD5UPHY942RpoYcPM"
            ),
            (
                "cRbB17stVTkcZ38o8xx6qRQod6Ucof55YgLa86yL8jtwVr1YfgcB",
                "tmP5MuXAzJEPS3GvjBeAiZUmrzYxuC6dUHv"
            ),
            (
                "cMm7vvjXYJGqLCTc1FcQmmteXYGNduUAVS25WCvyqQvWNTENabQF",
                "tmPeoJrhUAhcb4nXS3mCqdSBJuGTcX6s2sm"
            ),
            (
                "cVrMaRzQ4YkbQSJr595Lr9aem2UHomoFikSQNPKqHoZUdaicJBa6",
                "tmNEZVphFWo5vh5xfb1k5STFFMZ6yijzfKC"
            ),
            (
                "cNLN6kBQJ68w1idp9TiUDbiLPnZ9vm9THDXE6nGBER1g7Pv4GycX",
                "tmL1yemb1GvbS4SUzYQTirdGm7WSDREQgow"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH, &Network::Testnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2PKH, &Network::Testnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "91fek9Xs6SkDx9mm89hDNM84Y49yM446xKmdQDsLJ4uzUXX2jLg",
                "tmYkTUt1hBUcHyKtGpXYRM3tVrnL32fWDhi"
            ),
            (
                "934pAaCKAS9vb1GmiSc3tfmVbrvREF1VBo19YdEXGWEwZUee4pP",
                "tmHe2je7jqn9a7k4wpjidTCZTmFcKKUPgFu"
            ),
            (
                "91eKu9FmVPqPZTLMBwyGZygwtsFzxj49p3tF7DWGkLETUsWP7gv",
                "tmQWZNqKkn2JUJUa4DKZpzFZyN3tTLqZtMy"
            ),
            (
                "923PCzFXfoZ9sXrkBb4e1m8UzvWXATPY4uaxvLPGofCPM4AtS11",
                "tmJsXk5QzyvXCkNApr5PG6DXeHUfHbQWJsV"
            ),
            (
                "93UmH7crxTbPxq8mdJ9Vmzvk1nGEwVh4LDbg9iF7pJ2sezShhRX",
                "tmDM9R3iW5AGzmUWAPnMxCVkZYR7LLKbcnX"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH, &Network::Testnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2PKH, &Network::Testnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    #[test]
    fn test_p2pkh_invalid() {

        // Mismatched keypair

        let private_key = "KxYzZuBPkE3rnEEGCdsB6dCzxN1D4xoY5ogKoxbdUdkxbRzvgbij";
        let expected_address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt";

        let private_key = ZcashPrivateKey::from_wif(private_key).unwrap();
        let address = ZcashAddress::from_private_key(&private_key, &Format::P2PKH);
        assert_ne!(expected_address, address.to_string());

        let public_key = ZcashPublicKey::from_private_key(&private_key);
        let address = ZcashAddress::from_public_key(&public_key, &Format::P2PKH, &Network::Mainnet);
        assert_ne!(expected_address, address.to_string());

        // Invalid address length

        let address = "t";
        assert!(ZcashAddress::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3";
        assert!(ZcashAddress::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZ";
        assert!(ZcashAddress::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZtt1J8w8EMM1Rs26zJFu3";
        assert!(ZcashAddress::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZtt1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt";
        assert!(ZcashAddress::from_str(address).is_err());

    }
}

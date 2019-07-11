use crate::network::Network;
use crate::private_key::BitcoinPrivateKey;
use crate::public_key::BitcoinPublicKey;
use model::{Address, PrivateKey, crypto::{checksum, hash160}};

use base58::{FromBase58, ToBase58};
use serde::Serialize;
use std::fmt;
use std::str::FromStr;

/// Represents the format of a Bitcoin address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum Format {
    /// Pay-to-Pubkey Hash, e.g. 1NoZQSmjYHUZMbqLerwmT4xfe8A6mAo8TT
    P2PKH,
    /// SegWit Pay-to-Witness-Public-Key Hash, e.g. 34AgLJhwXrvmkZS1o5TrcdeevMt22Nar53
    P2SH_P2WPKH,
}

impl Format {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix(&self, network: &Network) -> u8 {
        match network {
            Network::Mainnet => match self {
                Format::P2PKH => 0x00,
                Format::P2SH_P2WPKH => 0x05
            },
            Network::Testnet => match self {
                Format::P2PKH => 0x6F,
                Format::P2SH_P2WPKH => 0xC4
            },
        }
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: u8) -> Result<Self, &'static str> {
        match prefix {
            0x00 | 0x6F => Ok(Format::P2PKH),
            0x05 | 0xC4 => Ok(Format::P2SH_P2WPKH),
            _ => return Err("invalid address prefix")
        }
    }
}

/// Represents a Bitcoin address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinAddress {
    /// The Bitcoin address
    pub address: String,
    /// The format of the address
    pub format: Format,
    /// The network on which this address is usable
    pub network: Network,
}

impl Address for BitcoinAddress {
    type Format = Format;
    type Network = Network;
    type PrivateKey = BitcoinPrivateKey;
    type PublicKey = BitcoinPublicKey;

    /// Returns the address corresponding to the given Bitcoin private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Self {
        let public_key = private_key.to_public_key();
        match format {
            Format::P2PKH => Self::p2pkh(&public_key, &private_key.network),
            Format::P2SH_P2WPKH => Self::p2sh_p2wpkh(&public_key, &private_key.network),
        }
    }

    /// Returns the address corresponding to the given Bitcoin public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
        network: &Self::Network
    ) -> Self {
        match format {
            Format::P2PKH => Self::p2pkh(public_key, &network),
            Format::P2SH_P2WPKH => Self::p2sh_p2wpkh(public_key, &network),
        }
    }
}

impl BitcoinAddress {
    /// Returns a P2PKH address from a given Bitcoin public key.
    pub fn p2pkh(public_key: &BitcoinPublicKey, network: &Network) -> Self {
        let public_key = match public_key.compressed {
            true => public_key.public_key.serialize().to_vec(),
            false => public_key.public_key.serialize_uncompressed().to_vec()
        };

        let mut address = [0u8; 25];
        address[0] = Format::P2PKH.to_address_prefix(network);
        address[1..21].copy_from_slice(&hash160(&public_key));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Self {
            address: address.to_base58(),
            format: Format::P2PKH,
            network: network.clone(),
        }
    }

    /// Returns a P2SH_P2WPKH address from a given Bitcoin public key.
    pub fn p2sh_p2wpkh(public_key: &BitcoinPublicKey, network: &Network) -> Self {
        let mut redeem = [0u8; 22];
        redeem[1] = 0x14;
        redeem[2..].copy_from_slice(&hash160(&public_key.public_key.serialize()));

        let mut address = [0u8; 25];
        address[0] = Format::P2SH_P2WPKH.to_address_prefix(network);
        address[1..21].copy_from_slice(&hash160(&redeem));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Self {
            address: address.to_base58(),
            format: Format::P2SH_P2WPKH,
            network: network.clone(),
        }
    }
}

impl FromStr for BitcoinAddress {
    type Err = &'static str;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() > 50 {
            return Err("invalid character length");
        }

        let data = address.from_base58().expect("invalid base58 format");
        if data.len() != 25 {
            return Err("invalid byte length");
        }

        let format = Format::from_address_prefix(data[0])?;
        let network = Network::from_address_prefix(data[0])?;

        Ok(Self { address: address.into(), format, network })
    }
}

impl fmt::Display for BitcoinAddress {
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
        private_key: &BitcoinPrivateKey,
        format: &Format,
    ) {
        let address = BitcoinAddress::from_private_key(private_key, format);
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key(
        expected_address: &str,
        public_key: &BitcoinPublicKey,
        format: &Format,
        network: &Network,
    ) {
        let address = BitcoinAddress::from_public_key(public_key, format, network);
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str(expected_address: &str, expected_format: &Format, expected_network: &Network) {
        let address = BitcoinAddress::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
        assert_eq!(*expected_network, address.network);
    }

    fn test_to_str(expected_address: &str, address: &BitcoinAddress) {
        assert_eq!(expected_address, address.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
            "L2o7RUmise9WoxNzmnVZeK83Mmt5Nn1NBpeftbthG5nsLWCzSKVg",
            "1GUwicFwsZbdE3XyJYjmPryiiuTiK7mZgS"
            ),
            (
            "KzjKw25tuQoiDyQjUG38ZRNBdnfr5eMBnTsU4JahrVDwFCpRZP1J",
            "1J2shZV5b53GRVmTqmr3tJhkVbBML29C1z"
            ),
            (
            "L2N8YRtxNMAVFAtxBt9PFSADtdvbmzFFHLSU61CtLdhYhrCGPfWh",
            "13TdfCiGPagApSJZu1o1Y3mpfqpp6oK2GB"
            ),
            (
            "KwXH1Mu4FBtGN9nRn2VkBpienaVGZKvCAkZAdE96kK71dHR1oDRs",
            "1HaeDGHf3A2Uxeh3sKjVLYTn1hnEyuzLjF"
            ),
            (
            "KwN7qiBnU4GNhboBhuPaPaFingTDKU4r27pGggwQYz865TvBT74V",
            "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                let public_key = BitcoinPublicKey::from_private_key(&private_key);
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
                let address = BitcoinAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "5K9VY2kaJ264Pj4ygobGLk7JJMgZ2i6wQ9FFKEBxoFtKeAXPHYm",
                "18Bap2Lh5HJckiZcg8SYXoF5iPxkUoCN8u"
            ),
            (
                "5KiudZRwr9wH5auJaW66WK3CGR1UzL7ZXiicvZEEaFScbbEt9Qs",
                "192JSK8wNP867JGxHNHay3obNSXqEyyhtx"
            ),
            (
                "5KCxYELatMGyVZfZFcSAw1Hz4ngiURKS22x7ydNRxcXfUzhgWMH",
                "1NoZQSmjYHUZMbqLerwmT4xfe8A6mAo8TT"
            ),
            (
                "5KT9CMP2Kgh2Afi8GbmFAHJXsH5DhcpH9KY3aH4Hkv5W6dASy7F",
                "1NyGFd49x4nqoau8RJvjf9tGZkoUNjwd5a"
            ),
            (
                "5J4cXobHh2cF2MHpLvTFjEHZCtrNHzyDzKGE8LuST2VWP129pAE",
                "17nsg1F155BR6ie2miiLrSnMhF8GWcGq6V"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                let public_key = BitcoinPublicKey::from_private_key(&private_key);
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
                let address = BitcoinAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX",
                "mwCDgjeRgGpfTMY1waYAJF2dGz4Q5XAx6w"
            ),
            (
                "cNp5uMWdh68Nk3pwShjxsSwhGPoCYgFvE1ANuPsk6qhcT4Jvp57n",
                "myH91eNrQKuuM7TeQYYddzL4URn6HiYbxW"
            ),
            (
                "cN9aUHNMMLT9yqBJ3S5qnEPtP11nhT7ivkFK1FqNYQMozZPgMTjJ",
                "mho8tsQtF7fx2bPKudMcXvGpUVYRHHiH4m"
            ),
            (
                "cSRpda6Bhog5SUyot96HSwSzn7FZNWzudKzoCzkgZrf9hUaL3Ass",
                "n3DgWHuAkg7eiPGH5gP8jeg3SbHBhuPJWS"
            ),
            (
                "cTqLNf3iCaW61ofgmyf4ZxChUL8DZoCEPmNTCKRsexLSdNuGWQT1",
                "mjhMXrTdq4X1dcqTaNDjwGdVaJEGBKpCRj"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                let public_key = BitcoinPublicKey::from_private_key(&private_key);
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
                let address = BitcoinAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "934pVYUzZ7Sm4ZSP7MtXaQXAcMhZHpFHFBvzfW3epFgk5cWeYih",
                "my55YLK4BmM8AyUW5px2HSSKL4yzUE5Pho"
            ),
            (
                "91dTfyLPPneZA6RsAXqNuT6qTQdAuuGVCUjmBtzgd1Tnd4RQT5K",
                "mw4afqNgGjn34okVmv9qH2WkvhfyTyNbde"
            ),
            (
                "92GweXA6j4RCF3zHXGGy2ShJq6T7u9rrjmuYd9ktLHgNrWznzUC",
                "moYi3FQZKtcc66edT3uMwVQCcswenpNscU"
            ),
            (
                "92QAQdzrEDkMExM9hHV5faWqKTdXcTgXguRBcyAyYqFCjVzhDLE",
                "mpRYQJ64ofurTCA3KKkaCjjUNqjYkUvB4w"
            ),
            (
                "92H9Kf4ikaqNAJLc5tbwvbmiBWJzNDGtYmnvrigZeDVD3aqJ85Q",
                "mvqRXtgQKqumMosPY3dLvhdYsQJV2AswkA"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                let public_key = BitcoinPublicKey::from_private_key(&private_key);
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
                let address = BitcoinAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2sh_p2wpkh_mainnet {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "L3YPi4msjWdkqiH3ojfg3nwDmNYBrDScAtcugYBJSgsc3HTcqqjP",
                "38EMCierP738rgYVHjj1qJANHKgx1166TN"
            ),
            (
                "KxxFoGgBdqqyGznT6he2wKYcFKm5urSANec7qjLeu3caEadSo5pv",
                "3Kc9Vqzi4eUn42g1KWewVPvtTpWpUwjNFv"
            ),
            (
                "KziUnVFNBniwmvei7JvNJNcQZ27TDZe5VNn7ieRNK7QgMEVfKdo9",
                "3C2niRgmFP2kz47AAWASqq5nWobDke1AfJ"
            ),
            (
                "Kx5veRe18jnV1rZiJA7Xerh5qLpwnbjV38r83sKcF1W9d1K2TGSp",
                "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK"
            ),
            (
                "L4RrcBy6hZMw3xD4eAFXDTWPhasd9N3rYrYgfiR9pnGuLdv7UsWZ",
                "3LW5tQGWBCiRLfCgk1FEUpwKoymFF8Lk7P"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2SH_P2WPKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                let public_key = BitcoinPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2SH_P2WPKH, &Network::Mainnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2SH_P2WPKH, &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2sh_p2wpkh_testnet {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cSoLwgnCNXck57BGxdGRV4SQ42EUExV6ykdMK1RKwcEaB9MDZWki",
                "2N9e892o8DNZs25xHBwRPZLsrZK3dBsrH3d"
            ),
            (
                "cQEUStvLToCNEQ6QGPyTmGFCTiMWWzQDkkj2tUPEiAzafybgUyu4",
                "2MwX52EZPfK1sq12H3ikgTybrUvKG62b9rV"
            ),
            (
                "cRv6jkNhTNEL7563ezNuwWP9W7gEcjh19YbmHtTbrDUQsXF5PjoG",
                "2N2XaYpYxX6C6attRQ1NXJUgZdm861CPHJ7"
            ),
            (
                "cNyZJwad53Y38RthGrmYyoHAtsT7cPisjW92HJ4RcAP1mC6xBpSm",
                "2N3HzUQ4DzfEbxYp3XtpEKBBSdBS1uc2DLk"
            ),
            (
                "cUqEZZwzvdWv6pmnWV5eb68hNeWt3jDZgtCGf66rqk3bnbsXArVE",
                "2N5isk4qJHAKfLV987ePAqjLobJkrWVCuhj"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2SH_P2WPKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
                let public_key = BitcoinPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2SH_P2WPKH, &Network::Testnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2SH_P2WPKH, &Network::Testnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    #[test]
    fn test_p2pkh_invalid() {

        // Mismatched keypair

        let private_key = "5K9VY2kaJ264Pj4ygobGLk7JJMgZ2i6wQ9FFKEBxoFtKeAXPHYm";
        let expected_address = "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J";

        let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
        let address = BitcoinAddress::from_private_key(&private_key, &Format::P2PKH);
        assert_ne!(expected_address, address.to_string());

        let public_key = BitcoinPublicKey::from_private_key(&private_key);
        let address = BitcoinAddress::from_public_key(&public_key, &Format::P2PKH, &Network::Mainnet);
        assert_ne!(expected_address, address.to_string());

        // Invalid address length

        let address = "1";
        assert!(BitcoinAddress::from_str(address).is_err());

        let address = "12WMrNLRosydPNN";
        assert!(BitcoinAddress::from_str(address).is_err());

        let address = "12WMrNLRosydPNNYM96dwk9jDv8rDRom3";
        assert!(BitcoinAddress::from_str(address).is_err());

        let address = "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J12WMrNLRosydPNNYM";
        assert!(BitcoinAddress::from_str(address).is_err());

        let address = "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J12WMrNLRosydPNNYM96dwk9jDv8rDRom3J";
        assert!(BitcoinAddress::from_str(address).is_err());

    }

    #[test]
    fn test_p2sh_p2wpkh_invalid() {

        // Mismatched keypair

        let private_key = "L3YPi4msjWdkqiH3ojfg3nwDmNYBrDScAtcugYBJSgsc3HTcqqjP";
        let expected_address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK";

        let private_key = BitcoinPrivateKey::from_wif(private_key).unwrap();
        let address = BitcoinAddress::from_private_key(&private_key, &Format::P2SH_P2WPKH);
        assert_ne!(expected_address, address.to_string());

        let public_key = BitcoinPublicKey::from_private_key(&private_key);
        let address = BitcoinAddress::from_public_key(&public_key, &Format::P2SH_P2WPKH, &Network::Mainnet);
        assert_ne!(expected_address, address.to_string());

        // Invalid address length

        let address = "3";
        assert!(BitcoinAddress::from_str(address).is_err());

        let address = "3Pai7Ly86pddxxwZ7";
        assert!(BitcoinAddress::from_str(address).is_err());

        let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNY";
        assert!(BitcoinAddress::from_str(address).is_err());

        let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK3Pai7Ly86pddxxwZ7";
        assert!(BitcoinAddress::from_str(address).is_err());

        let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK";
        assert!(BitcoinAddress::from_str(address).is_err());

    }
}

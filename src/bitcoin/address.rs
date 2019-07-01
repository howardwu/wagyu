extern crate base58;

use std::fmt;

use bitcoin::network::{MAINNET_ADDRESS_BYTE, TESTNET_ADDRESS_BYTE};
use bitcoin::privatekey::PrivateKey;
use bitcoin::utils::{checksum, hash160};
use traits::Network;

use self::base58::ToBase58;

/// Represents a Bitcoin Address
#[derive(Serialize, Debug)]
pub struct Address {
    pub wif: String,
    pub network: Network,
    pub address_type: Type,
}

/// Represents type of Bitcoin Address
#[derive(Serialize, Debug, Clone)]
pub enum Type {
    P2PKH,
    P2WPKH_P2SH,
}

impl Address {
    /// Returns an Address given a PrivateKey object
    pub fn from_private_key(private_key: &PrivateKey, address_type: Type) -> Address {
        match address_type {
            Type::P2PKH => Address::p2pkh(private_key),
            Type::P2WPKH_P2SH => Address::p2wpkh_p2sh(private_key),
        }
    }

    /// Returns P2WPKH_P2SH address from PrivateKey
    fn p2wpkh_p2sh(private_key: &PrivateKey) -> Address {
        let public_key = private_key.to_public_key().serialize();
        let mut address_bytes = [0u8; 25];
        let version_byte = 0x05;

        let witness_program = hash160(&public_key);
        let mut redeem_script = [0u8; 22];
        redeem_script[0] = 0x00;
        redeem_script[1] = 0x14;
        redeem_script[2..].copy_from_slice(&witness_program);

        let script_hash = hash160(&redeem_script);

        address_bytes[0] = version_byte;
        address_bytes[1..21].copy_from_slice(&script_hash);

        let checksum_bytes = checksum(&address_bytes[0..21]); // Calculate Checksum
        address_bytes[21..25].copy_from_slice(&checksum_bytes[0..4]); // Append Checksum Bytes

        Address {
            wif: address_bytes.to_base58(),
            network: private_key.network().clone(),
            address_type: Type::P2WPKH_P2SH,
        }
    }

    /// Returns P2PKH address from PrivateKey
    fn p2pkh(private_key: &PrivateKey) -> Address {
        let public_key = if *private_key.compressed() {
            private_key.to_public_key().serialize().to_vec()
        } else {
            private_key
                .to_public_key()
                .serialize_uncompressed()
                .to_vec()
        };
        let pub_key_hash = hash160(&public_key);
        let mut address_bytes = [0u8; 25];

        let network_byte = match private_key.network() {
            // Prepend Network Bytes
            Network::Testnet => TESTNET_ADDRESS_BYTE,
            _ => MAINNET_ADDRESS_BYTE,
        };

        address_bytes[0] = network_byte;
        address_bytes[1..21].copy_from_slice(&pub_key_hash);

        let checksum_bytes = checksum(&address_bytes[0..21]); // Calculate Checksum
        address_bytes[21..25].copy_from_slice(&checksum_bytes[0..4]); // Append Checksum Bytes

        Address {
            wif: address_bytes.to_base58(),
            network: private_key.network().clone(),
            address_type: Type::P2PKH,
        }
    }

    /// Returns an Address given a private key in Wallet Import Format
    pub fn from_wif(wif: &str, address_type: Type) -> Address {
        let private_key = PrivateKey::from_wif(wif).expect("Error deriving PrivateKey from WIF");
        Address::from_private_key(&private_key, address_type)
    }

    pub fn wif(&self) -> &str {
        &self.wif
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.wif)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_p2pkh_pairs(private_keys: [&str; 5], addresses: [&str; 5]) {
        let key_address_pairs = private_keys.iter().zip(addresses.iter());
        key_address_pairs.for_each(|(&private_key_wif, &expected_address)| {
            let address = Address::from_wif(&private_key_wif, Type::P2PKH);
            assert_eq!(expected_address, address.wif);
        });
    }

    fn test_p2wpkh_pair(private_key: &str, expected_address: &str) {
        let address = Address::from_wif(&private_key, Type::P2WPKH_P2SH);
        println!("{}, {}", address, expected_address);
        assert_eq!(expected_address, address.wif);
    }

    #[test]
    fn test_p2wpkh() {
        test_p2wpkh_pair(
            "Kxr9tQED9H44gCmp6HAdmemAzU3n84H3dGkuWTKvE23JgHMW8gct",
            "34AgLJhwXrvmkZS1o5TrcdeevMt22Nar53",
        );
    }

    #[test]
    fn test_testnet_uncompressed_p2pkh() {
        let private_keys = [
            "934pVYUzZ7Sm4ZSP7MtXaQXAcMhZHpFHFBvzfW3epFgk5cWeYih",
            "91dTfyLPPneZA6RsAXqNuT6qTQdAuuGVCUjmBtzgd1Tnd4RQT5K",
            "92GweXA6j4RCF3zHXGGy2ShJq6T7u9rrjmuYd9ktLHgNrWznzUC",
            "92QAQdzrEDkMExM9hHV5faWqKTdXcTgXguRBcyAyYqFCjVzhDLE",
            "92H9Kf4ikaqNAJLc5tbwvbmiBWJzNDGtYmnvrigZeDVD3aqJ85Q",
        ];
        let addresses = [
            "my55YLK4BmM8AyUW5px2HSSKL4yzUE5Pho",
            "mw4afqNgGjn34okVmv9qH2WkvhfyTyNbde",
            "moYi3FQZKtcc66edT3uMwVQCcswenpNscU",
            "mpRYQJ64ofurTCA3KKkaCjjUNqjYkUvB4w",
            "mvqRXtgQKqumMosPY3dLvhdYsQJV2AswkA",
        ];

        test_p2pkh_pairs(private_keys, addresses);
    }

    #[test]
    fn test_mainnet_uncompressed_p2pkh() {
        let private_keys = [
            "5K9VY2kaJ264Pj4ygobGLk7JJMgZ2i6wQ9FFKEBxoFtKeAXPHYm",
            "5KiudZRwr9wH5auJaW66WK3CGR1UzL7ZXiicvZEEaFScbbEt9Qs",
            "5KCxYELatMGyVZfZFcSAw1Hz4ngiURKS22x7ydNRxcXfUzhgWMH",
            "5KT9CMP2Kgh2Afi8GbmFAHJXsH5DhcpH9KY3aH4Hkv5W6dASy7F",
            "5J4cXobHh2cF2MHpLvTFjEHZCtrNHzyDzKGE8LuST2VWP129pAE",
        ];
        let addresses = [
            "18Bap2Lh5HJckiZcg8SYXoF5iPxkUoCN8u",
            "192JSK8wNP867JGxHNHay3obNSXqEyyhtx",
            "1NoZQSmjYHUZMbqLerwmT4xfe8A6mAo8TT",
            "1NyGFd49x4nqoau8RJvjf9tGZkoUNjwd5a",
            "17nsg1F155BR6ie2miiLrSnMhF8GWcGq6V",
        ];

        test_p2pkh_pairs(private_keys, addresses);
    }

    #[test]
    fn test_mainnet_compressed_p2pkh() {
        let private_keys = [
            "L2o7RUmise9WoxNzmnVZeK83Mmt5Nn1NBpeftbthG5nsLWCzSKVg",
            "KzjKw25tuQoiDyQjUG38ZRNBdnfr5eMBnTsU4JahrVDwFCpRZP1J",
            "L2N8YRtxNMAVFAtxBt9PFSADtdvbmzFFHLSU61CtLdhYhrCGPfWh",
            "KwXH1Mu4FBtGN9nRn2VkBpienaVGZKvCAkZAdE96kK71dHR1oDRs",
            "KwN7qiBnU4GNhboBhuPaPaFingTDKU4r27pGggwQYz865TvBT74V",
        ];
        let addresses = [
            "1GUwicFwsZbdE3XyJYjmPryiiuTiK7mZgS",
            "1J2shZV5b53GRVmTqmr3tJhkVbBML29C1z",
            "13TdfCiGPagApSJZu1o1Y3mpfqpp6oK2GB",
            "1HaeDGHf3A2Uxeh3sKjVLYTn1hnEyuzLjF",
            "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J",
        ];

        test_p2pkh_pairs(private_keys, addresses);
    }

    #[test]
    fn test_testnet_compressed_p2pkh() {
        let private_keys = [
            "cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX",
            "cNp5uMWdh68Nk3pwShjxsSwhGPoCYgFvE1ANuPsk6qhcT4Jvp57n",
            "cN9aUHNMMLT9yqBJ3S5qnEPtP11nhT7ivkFK1FqNYQMozZPgMTjJ",
            "cSRpda6Bhog5SUyot96HSwSzn7FZNWzudKzoCzkgZrf9hUaL3Ass",
            "cTqLNf3iCaW61ofgmyf4ZxChUL8DZoCEPmNTCKRsexLSdNuGWQT1",
        ];
        let addresses = [
            "mwCDgjeRgGpfTMY1waYAJF2dGz4Q5XAx6w",
            "myH91eNrQKuuM7TeQYYddzL4URn6HiYbxW",
            "mho8tsQtF7fx2bPKudMcXvGpUVYRHHiH4m",
            "n3DgWHuAkg7eiPGH5gP8jeg3SbHBhuPJWS",
            "mjhMXrTdq4X1dcqTaNDjwGdVaJEGBKpCRj",
        ];

        test_p2pkh_pairs(private_keys, addresses);
    }
}

extern crate base58;
extern crate ripemd160;
extern crate sha2;

use self::base58::ToBase58;
use self::ripemd160::Ripemd160;
use self::sha2::{Digest, Sha256};
use network::{Network, MAINNET_ADDRESS_BYTE, TESTNET_ADDRESS_BYTE};
use privatekey::PrivateKey;
use std::fmt;
use utils::checksum;

/// Represents a Bitcoin Address
#[derive(Serialize, Debug)]
pub struct Address {
    pub wif: String,
    pub network: self::Network,
}

impl Address {
    /// Returns an Address given a PrivateKey object
    pub fn from_private_key(private_key: &PrivateKey) -> Address {
        let public_key = match private_key.compressed() {
            true => private_key.to_public_key().serialize().to_vec(),
            false => private_key
                .to_public_key()
                .serialize_uncompressed()
                .to_vec(),
        };
        let sha256_hash = Sha256::digest(&public_key); // Sha256 Hash
        let ripemd160_hash = Ripemd160::digest(&sha256_hash); // Ripemd160 Hash
        let mut address_bytes = [0u8; 25];

        let network_byte = match private_key.network() {
            // Prepend Network Bytes
            Network::Testnet => TESTNET_ADDRESS_BYTE,
            _ => MAINNET_ADDRESS_BYTE,
        };

        address_bytes[0] = network_byte;
        address_bytes[1..21].copy_from_slice(&ripemd160_hash);

        let checksum_bytes = checksum(&address_bytes[0..21]); // Calculate Checksum
        address_bytes[21..25].copy_from_slice(&checksum_bytes[0..4]); // Append Checksum Bytes

        Address {
            wif: address_bytes.to_base58(),
            network: private_key.network().clone(),
        }
    }

    /// Returns an Address given a private key in Wallet Import Format
    pub fn from_wif(wif: &str) -> Address {
        let private_key = PrivateKey::from_wif(wif).expect("Error deriving PrivateKey from WIF");
        Address::from_private_key(&private_key)
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

    fn test_private_key_address_pairs(private_keys: [&str; 5], addresses: [&str; 5]) {
        let key_address_pairs = private_keys.iter().zip(addresses.iter());
        key_address_pairs.for_each(|(&private_key_wif, &expected_address)| {
            let address = Address::from_wif(&private_key_wif);
            assert_eq!(expected_address, address.wif);
        });
    }

    #[test]
    fn test_testnet_uncompressed_private_key_to_address() {
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

        test_private_key_address_pairs(private_keys, addresses);
    }

    #[test]
    fn test_mainnet_uncompressed_private_key_to_address() {
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

        test_private_key_address_pairs(private_keys, addresses);
    }

    #[test]
    fn test_mainnet_compressed_private_key_to_address() {
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

        test_private_key_address_pairs(private_keys, addresses);
    }

    #[test]
    fn test_testnet_compressed_private_key_to_address() {
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

        test_private_key_address_pairs(private_keys, addresses);
    }
}

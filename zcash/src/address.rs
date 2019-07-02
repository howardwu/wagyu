use network::{Network, MAINNET_ADDRESS_BYTES, TESTNET_ADDRESS_BYTES};
use privatekey::PrivateKey;
use utils::checksum;

use base58::ToBase58;
use ripemd160::Ripemd160;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

/// Represents a Zcash t-address
#[derive(Serialize, Debug)]
pub struct Address {
    pub wif: String,
    pub network: Network,
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
        let mut address_bytes = [0u8; 26];

        let network_bytes = match private_key.network() {
            // Prepend Network Bytes
            Network::Testnet => TESTNET_ADDRESS_BYTES,
            _ => MAINNET_ADDRESS_BYTES,
        };

        address_bytes[0] = network_bytes[0];
        address_bytes[1] = network_bytes[1];
        address_bytes[2..22].copy_from_slice(&ripemd160_hash);

        let checksum_bytes = checksum(&address_bytes[0..22]); // Calculate Checksum
        address_bytes[22..26].copy_from_slice(&checksum_bytes[0..4]); // Append Checksum Bytes

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

    // fn test_private_key_address_pair(private_key: &str, expected_address: &str) {
    //     let address = Address::from_wif(&private_key);
    //     assert_eq!(expected_address, address.wif);
    // }

    #[test]
    fn test_mainnet_uncompressed_private_key_to_address() {
        let private_keys = [
            "5HwduFgmNrhcgXpD7TH2ZbqBzfET3FzRLwapJdZYUNyxPz6MYQU",
            "5KFcAbDaap4ZqF1pCTq6rKWU6bUZg3bnqHJYaCEh6NUu8aVTszm",
            "5KXotG2j5THVbdf2Uf87HPZFRNaVqZYrrBVnZzczyDVza39q94f",
            "5KPN7LeX6uzBpTYdC28xjgHkN5XbCKZVJiu9QquSCEFJcD7ndnv",
            "5JewwWXmgcdk9P762F3Pdr8RBcWfWVAAotq9mjSNBcEvZsQBJ32",
        ];
        let addresses = [
            "t1gxf6ykX23Ha3Bf1bKhjJzdxtCPratotJK",
            "t1QnYYpiVpmwHPtrRSJqypnDxG77284NUtj",
            "t1XEXEt3KeEYzycPTzn3invLivktYifWuXJ",
            "t1VxdN6a4T6RiSwgkNURkHhjLuoThvZWaHC",
            "t1XraTEGoX5QjnhAqDs9F8AqvDEh4zohhUQ",
        ];

        test_private_key_address_pairs(private_keys, addresses);
    }

    #[test]
    fn test_mainnet_compressed_private_key_to_address() {
        let private_keys = [
            "KxYzZuBPkE3rnEEGCdsB6dCzxN1D4xoY5ogKoxbdUdkxbRzvgbij",
            "KyuC6qNxMiuPEF4wp6eLsJuczLKqHsdsdSx5c3a1boY81mpahuR6",
            "KxNLHESzCRfzTfF9KGsF68QtV9fT9qFRAH5UKpVUdMvc4TTcBmhJ",
            "L5XgV3xUnqcqJyJm3JZmtZyj5i8FmUbuj9LCz9n3FA87Ertn2Qod",
            "L17dC6ZcGfKu84FGastka34sB8yV9fzgbKJaafVWi4zKs6ETnF2x",
        ];
        let addresses = [
            "t1MoMR1XdnPqLBWf5XkchWTkGNrveYLCaiM",
            "t1cnUnLfXZsb7gM7h9zD6QXm1wEDi4NxvTi",
            "t1VenYPx8HCiq6YFbuh1HbLGwtDZxQ5hQCr",
            "t1U9A7fh864FCzePbrXeUdjvuMfuCYKijbr",
            "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt",
        ];

        test_private_key_address_pairs(private_keys, addresses);
    }
}

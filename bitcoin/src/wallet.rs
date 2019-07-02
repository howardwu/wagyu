use address::{Address, Type};
use network::Network;
use privatekey::PrivateKey;

use serde::Serialize;
use serde_json::to_string_pretty;
use std::fmt;

/// A BitcoinWallet is represented by a PrivateKey and Address pair
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BitcoinWallet {
    pub private_key: PrivateKey,
    pub address: Address,
}

impl BitcoinWallet {
    /// Generates a new uncompressed BitcoinWallet for a given `network`
    pub fn new(network: Network, compressed: bool, address_type: &Type) -> BitcoinWallet {
        let private_key = if compressed {
            PrivateKey::new_compressed(network)
        } else {
            PrivateKey::new(network)
        };
        let address = Address::from_private_key(&private_key, &address_type);
        BitcoinWallet {
            private_key,
            address,
        }
    }

    /// Recovers a BitcoinWallet from a PrivateKey object
    pub fn from_private_key(private_key: PrivateKey, address_type: &Type) -> BitcoinWallet {
        let address = Address::from_private_key(&private_key, &address_type);
        BitcoinWallet {
            private_key,
            address,
        }
    }

    /// Recovers a BitcoinWallet from a Wallet Import Format string (a private key string)
    pub fn from_wif(private_key_wif: &str, address_type: &Type) -> BitcoinWallet {
        let private_key =
            PrivateKey::from_wif(private_key_wif).expect("Error creating Bitcoin Wallet from WIF");
        BitcoinWallet::from_private_key(private_key, address_type)
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn network(&self) -> &Network {
        self.private_key().network()
    }

    pub fn compressed(&self) -> &bool {
        self.private_key().compressed()
    }

    pub fn to_json(&self) -> String {
        to_string_pretty(&self).unwrap()
    }
}

impl fmt::Display for BitcoinWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "
        Private Key:    {}
        Address:        {}
        Network:        {}
        Compressed:     {}
        ",
            self.private_key().wif(),
            self.address().wif(),
            self.private_key().network(),
            self.private_key().compressed()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_wif(private_key_wif: &str, address_wif: &str) {
        let wallet = BitcoinWallet::from_wif(private_key_wif, &Type::P2PKH);
        assert_eq!(wallet.private_key().wif(), private_key_wif);
        assert_eq!(wallet.address().wif(), address_wif);
    }

    #[test]
    fn test_from_wif_mainnet_uncompressed() {
        test_from_wif(
            "5K6YcjP9R6R1dSbLskZsgcYnFd9Re2GG9HnTQFgU5Nqo9E4fbbQ",
            "1KQNWxEYh7pMv5rPxGQGc3mRbHqZjr8a8Q",
        );
    }

    #[test]
    fn test_from_wif_mainnet_compressed() {
        test_from_wif(
            "L2sUYi4k9Ltymqxaj1J6hquGjYYBkQaMqb5dXdoCWKQNer7LYHBp",
            "1D19u6K2Ad2dpBuG7BquxgJrcQRSzgSbgw",
        );
    }

    #[test]
    fn test_from_wif_testnet_uncompressed() {
        test_from_wif(
            "934pVYUzZ7Sm4ZSP7MtXaQXAcMhZHpFHFBvzfW3epFgk5cWeYih",
            "my55YLK4BmM8AyUW5px2HSSKL4yzUE5Pho",
        );
    }

    #[test]
    fn test_from_wif_testnet_compressed() {
        test_from_wif(
            "cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX",
            "mwCDgjeRgGpfTMY1waYAJF2dGz4Q5XAx6w",
        );
    }
}

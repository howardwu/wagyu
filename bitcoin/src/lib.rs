//! # Bitcoin
//!
//! A library for generating Bitcoin Wallets.
use address::Address;
use network::Network;
use privatekey::PrivateKey;
use std::fmt;

pub mod address;
pub mod network;
pub mod privatekey;


/// A BitcoinWallet is represented by a PrivateKey and Address pair
pub struct BitcoinWallet {
    pub private_key: PrivateKey,
    pub address: Address,
}

impl BitcoinWallet {
    /// Generates a new uncompressed BitcoinWallet for a given `network`
    pub fn new(network: Network) -> BitcoinWallet {
        BitcoinWallet::build(network, false)
    }

    /// Generates a new compressed BitcoinWallet for a given `network`
    pub fn new_compressed(network: Network) -> BitcoinWallet {
        BitcoinWallet::build(network, true)
    }

    fn build(network: Network, compressed: bool) -> BitcoinWallet {
        let private_key = if compressed {
            PrivateKey::new_compressed(network)
        } else {
            PrivateKey::new(network)
        };
        let address = Address::from_private_key(&private_key);
        BitcoinWallet { private_key, address }
    }

    /// Recovers a BitcoinWallet from a PrivateKey object
    pub fn from_private_key(private_key: PrivateKey) -> BitcoinWallet {
        let address = Address::from_private_key(&private_key);
        BitcoinWallet { private_key, address }
    }

    /// Recovers a BitcoinWallet from a Wallet Import Format string (a private key string)
    pub fn from_wif(private_key_wif: &str) -> BitcoinWallet {
        let private_key = PrivateKey::from_wif(private_key_wif).expect("Error creating Bitcoin Wallet from WIF");
        BitcoinWallet::from_private_key(private_key)
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn address(&self) -> &Address {
        &self.address
    }
}

impl fmt::Display for BitcoinWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "
        Private Key:    {}
        Address:        {}
        Network:        {}
        Compressed:     {}
        ", self.private_key().wif(), self.address().wif(), self.private_key().network(), self.private_key().compressed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_wif(private_key_wif: &str, address_wif: &str) {
        let wallet = BitcoinWallet::from_wif(private_key_wif);
        assert_eq!(wallet.private_key().wif(), private_key_wif);
        assert_eq!(wallet.address().wif(), address_wif);
    }

    #[test]
    fn test_from_wif_mainnet_uncompressed() {
        test_from_wif(
            "5K6YcjP9R6R1dSbLskZsgcYnFd9Re2GG9HnTQFgU5Nqo9E4fbbQ",
        "1KQNWxEYh7pMv5rPxGQGc3mRbHqZjr8a8Q"
        );
    }

    #[test]
    fn test_from_wif_mainnet_compressed() {
        test_from_wif(
            "L2sUYi4k9Ltymqxaj1J6hquGjYYBkQaMqb5dXdoCWKQNer7LYHBp",
            "1D19u6K2Ad2dpBuG7BquxgJrcQRSzgSbgw"
        );
    }

    #[test]
    fn test_from_wif_testnet_uncompressed() {
        test_from_wif(
            "934pVYUzZ7Sm4ZSP7MtXaQXAcMhZHpFHFBvzfW3epFgk5cWeYih",
            "my55YLK4BmM8AyUW5px2HSSKL4yzUE5Pho"
        );
    }

    #[test]
    fn test_from_wif_testnet_compressed() {
        test_from_wif(
            "cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX",
            "mwCDgjeRgGpfTMY1waYAJF2dGz4Q5XAx6w"
        );
    }
}

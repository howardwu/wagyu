use address::{Address, Type};
use network::Network;
use private_key::PrivateKey;

use serde::Serialize;
use serde_json::to_string_pretty;
use std::fmt;

/// A ZcashWallet is represented by a PrivateKey and Address pair
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ZcashWallet {
    pub private_key: PrivateKey,
    pub address: Address,
}

impl ZcashWallet {
    /// Generates a new uncompressed ZcashWallet for a given `network`
    pub fn new(network: Network) -> ZcashWallet {
        ZcashWallet::build(network, false)
    }

    /// Generates a new compressed ZcashWallet for a given `network`
    pub fn new_compressed(network: Network) -> ZcashWallet {
        ZcashWallet::build(network, true)
    }

    fn build(network: Network, compressed: bool) -> ZcashWallet {
        let private_key = if compressed {
            PrivateKey::new_compressed(network)
        } else {
            PrivateKey::new(network)
        };
        let address = Address::from_private_key(&private_key);
        ZcashWallet {
            private_key,
            address,
        }
    }

    /// Recovers a ZcashWallet from a PrivateKey object
    pub fn from_private_key(private_key: PrivateKey) -> ZcashWallet {
        let address = Address::from_private_key(&private_key);
        ZcashWallet {
            private_key,
            address,
        }
    }

    /// Recovers a ZcashWallet from a Wallet Import Format string (a private key string)
    pub fn from_wif(private_key_wif: &str) -> ZcashWallet {
        let private_key =
            PrivateKey::from_wif(private_key_wif).expect("Error creating Bitcoin Wallet from WIF");
        ZcashWallet::from_private_key(private_key)
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

impl fmt::Display for ZcashWallet {
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

    fn test_wallet_functionality(wallet: ZcashWallet, network: Network) {
        let mut address = Address::from_private_key(wallet.private_key());
        assert_eq!(wallet.address().to_string(), address.to_string());

        address = Address::from_wif(wallet.private_key().wif());
        assert_eq!(wallet.address().to_string(), address.to_string());

        assert_eq!(wallet.private_key().network().to_string(), network.to_string());
        assert_eq!(wallet.address().network.to_string(), network.to_string());
    }

    fn test_from_wif(private_key_wif: &str, address_wif: &str, network: Network) {
        let wallet = ZcashWallet::from_wif(private_key_wif);
        assert_eq!(wallet.private_key().wif(), private_key_wif);
        assert_eq!(wallet.private_key().network().to_string(), network.to_string());
        assert_eq!(wallet.address().wif(), address_wif);
    }

    #[test]
    fn test_new() {
        test_wallet_functionality(ZcashWallet::new(Network::Mainnet), Network::Mainnet);
        test_wallet_functionality(ZcashWallet::new(Network::Testnet), Network::Testnet);
    }

    #[test]
    fn test_new_compressed() {
        test_wallet_functionality(ZcashWallet::new_compressed(Network::Mainnet), Network::Mainnet);
        test_wallet_functionality(ZcashWallet::new_compressed(Network::Testnet), Network::Testnet);
    }

    #[test]
    fn test_from_wif_mainnet_uncompressed() {
        test_from_wif(
            "5KBUiRw5cDH5iGofacFTRTFseRgkg8bP1Vq4w7NeZEAUMUzuZ48",
            "t1cGCFCHzujWqMj6sBSKhCkbbXvAG3TA7eu",
            Network::Mainnet
        );
    }

    #[test]
    fn test_from_wif_mainnet_compressed() {
        test_from_wif(
            "L3FFKs3hLRByoAkyHLaocvteYBxTmiWk9CFAMq8YmF6oj1UzfkmF",
            "t1Qu2mQ1SGDvpQg1zXc5FXQK3kTwMtqVrab",
            Network::Mainnet
        );
    }

    #[test]
    fn test_from_wif_testnet_uncompressed() {
        test_from_wif(
            "934pVYUzZ7Sm4ZSP7MtXaQXAcMhZHpFHFBvzfW3epFgk5cWeYih",
            "tmTGUaT8cjjCy8kFDyR6WSzzfKifBpxkASe",
            Network::Testnet
        );
    }

    #[test]
    fn test_from_wif_testnet_compressed() {
        test_from_wif(
            "cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX",
            "tmRPcirTzEEgWR8JjqAgeToayGdjbVQRJcC",
            Network::Testnet
        );
    }
}

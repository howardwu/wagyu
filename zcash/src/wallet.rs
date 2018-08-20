extern crate serde_json;

use self::serde_json::to_string_pretty;
use address::Address;
use network::Network;
use privatekey::PrivateKey;
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

    fn test_from_wif(private_key_wif: &str, address_wif: &str) {
        let wallet = ZcashWallet::from_wif(private_key_wif);
        assert_eq!(wallet.private_key().wif(), private_key_wif);
        assert_eq!(wallet.address().wif(), address_wif);
    }

    #[test]
    fn test_from_wif_mainnet_uncompressed() {
        test_from_wif(
            "5KBUiRw5cDH5iGofacFTRTFseRgkg8bP1Vq4w7NeZEAUMUzuZ48",
            "t1cGCFCHzujWqMj6sBSKhCkbbXvAG3TA7eu",
        );
    }

    #[test]
    fn test_from_wif_mainnet_compressed() {
        test_from_wif(
            "L3FFKs3hLRByoAkyHLaocvteYBxTmiWk9CFAMq8YmF6oj1UzfkmF",
            "t1Qu2mQ1SGDvpQg1zXc5FXQK3kTwMtqVrab",
        );
    }

    // #[test]
    // fn test_from_wif_testnet_uncompressed() {
    //     test_from_wif(
    //         "934pVYUzZ7Sm4ZSP7MtXaQXAcMhZHpFHFBvzfW3epFgk5cWeYih",
    //         "my55YLK4BmM8AyUW5px2HSSKL4yzUE5Pho",
    //     );
    // }

    // #[test]
    // fn test_from_wif_testnet_compressed() {
    //     test_from_wif(
    //         "cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX",
    //         "mwCDgjeRgGpfTMY1waYAJF2dGz4Q5XAx6w",
    //     );
    // }
}

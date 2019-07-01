extern crate serde_json;

use std::fmt;

use traits::Config;
use traits::Network;
use traits::Wallet;
use zcash::address::Address;
use zcash::privatekey::PrivateKey;

use self::serde_json::to_string_pretty;

/// A ZcashWallet is represented by a PrivateKey and Address pair
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ZcashWallet {
    pub private_key: PrivateKey,
    pub address: Address,
}

impl Wallet for ZcashWallet {
    /// Generates a new uncompressed ZcashWallet for a given `network`
    fn new(config: &Config) -> ZcashWallet {
        ZcashWallet::build(&config)
    }

    /// Recovers a ZcashWallet from a Wallet Import Format string (a private key string)
    fn from_wif(private_key_wif: &str) -> ZcashWallet {
        let private_key =
            PrivateKey::from_wif(private_key_wif).expect("Error creating Bitcoin Wallet from WIF");
        ZcashWallet::from_private_key(private_key)
    }

    fn to_json(&self) -> String {
        to_string_pretty(&self).unwrap()
    }
}

impl ZcashWallet {
    fn build(config: &Config) -> ZcashWallet {
        let private_key = if config.compressed {
            PrivateKey::new_compressed(config.network.clone())
        } else {
            PrivateKey::new(config.network.clone())
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
}

extern crate serde_json;

use self::serde_json::to_string_pretty;
use address::Address;
use keypair::KeyPair;
use std::fmt;

/// An EthereumWallet is represented by a PrivateKey and Address pair
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EthereumWallet {
    pub keypair: KeyPair,
    pub address: Address,
}

impl EthereumWallet {
    /// Generates a new uncompressed EthereumWallet for a given `network`
    pub fn new() -> EthereumWallet {
        let keypair = KeyPair::new();
        let address = Address::from_key_pair(&keypair);
        EthereumWallet {
            keypair,
            address,
        }
    }

    /// Recovers a EthereumWallet from a KeyPair object
    pub fn from_key_pair(keypair: KeyPair) -> EthereumWallet {
        let address = Address::from_key_pair(&keypair);
        EthereumWallet {
            keypair,
            address,
        }
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn to_json(&self) -> String {
        to_string_pretty(&self).unwrap()
    }
}

impl fmt::Display for EthereumWallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "
        Private Key:    {}
        Address:        {}
        ",
            self.keypair(),
            self.address()
        )
    }
}
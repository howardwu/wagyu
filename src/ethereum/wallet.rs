extern crate serde_json;

use self::serde_json::to_string_pretty;
use ethereum::address::Address;
use ethereum::keypair::KeyPair;
use std::fmt;

/// An EthereumWallet is represented by a PrivateKey and Address pair
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EthereumWallet {
    #[serde(flatten)]
    pub keypair: KeyPair,
    #[serde(flatten)]
    pub address: Address,
}

impl EthereumWallet {
    /// Generates a new uncompressed EthereumWallet for a given `network`
    pub fn new() -> EthereumWallet {
        let keypair = KeyPair::new();
        let address = Address::from_key_pair(&keypair);
        EthereumWallet { keypair, address }
    }

    /// Recovers a EthereumWallet from a KeyPair object
    pub fn from_key_pair(keypair: KeyPair) -> EthereumWallet {
        let address = Address::from_key_pair(&keypair);
        EthereumWallet { keypair, address }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_private_key_string(private_key_string: &str, address_string: &str) {
        let secret_key = KeyPair::from_secret_key_string(private_key_string);
        let private_key = KeyPair::private_key_from_secret_key(secret_key);

        let key_pair = KeyPair::from_secret_key(secret_key);
        let wallet = EthereumWallet::from_key_pair(key_pair);

        assert_eq!(&private_key, private_key_string);
        assert_eq!(wallet.address().address(), address_string);
    }

    #[test]
    fn test_import() {
        test_from_private_key_string(
            "bca329365b086a46a47e0ccce37059c266d1d408476be222eb5bafbd07cce698",
            "0x1694D72a05a6038d3b195DAcb450e40B7ec8d50c",
        );

        test_from_private_key_string(
            "17cad55df5fa77d0de1806cebbc77eb2f5609ff94310dad89844ce0806bdcd0d",
            "0x585a1281c2ad7Cf3F4c01d6f05EF9c4F7E1c9aDc",
        );
    }
}

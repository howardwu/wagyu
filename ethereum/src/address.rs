use crate::format::EthereumFormat;
use crate::private_key::EthereumPrivateKey;
use crate::public_key::EthereumPublicKey;
use wagyu_model::{to_hex_string, Address, AddressError, PrivateKey};

use regex::Regex;
use serde::Serialize;
use std::{convert::TryFrom, fmt, str::FromStr};
use tiny_keccak::keccak256;

/// Represents an Ethereum address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash)]
pub struct EthereumAddress(String);

impl Address for EthereumAddress {
    type Format = EthereumFormat;
    type PrivateKey = EthereumPrivateKey;
    type PublicKey = EthereumPublicKey;

    /// Returns the address corresponding to the given private key.
    fn from_private_key(private_key: &Self::PrivateKey, _format: &Self::Format) -> Result<Self, AddressError> {
        Self::from_public_key(&private_key.to_public_key(), _format)
    }

    /// Returns the address corresponding to the given public key.
    fn from_public_key(public_key: &Self::PublicKey, _: &Self::Format) -> Result<Self, AddressError> {
        Ok(Self::checksum_address(public_key))
    }
}

impl EthereumAddress {
    /// Returns the checksum address given a public key.
    /// Adheres to EIP-55 (https://eips.ethereum.org/EIPS/eip-55).
    pub fn checksum_address(public_key: &EthereumPublicKey) -> Self {
        let hash = keccak256(&public_key.to_secp256k1_public_key().serialize()[1..]);
        let address = to_hex_string(&hash[12..]).to_lowercase();

        let hash = to_hex_string(&keccak256(address.as_bytes()));
        let mut checksum_address = "0x".to_string();
        for c in 0..40 {
            let ch = match &hash[c..=c] {
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => address[c..=c].to_lowercase(),
                _ => address[c..=c].to_uppercase(),
            };
            checksum_address.push_str(&ch);
        }

        EthereumAddress(checksum_address)
    }
}

impl<'a> TryFrom<&'a str> for EthereumAddress {
    type Error = AddressError;

    fn try_from(address: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(address)
    }
}

impl FromStr for EthereumAddress {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        let regex = Regex::new(r"^0x").unwrap();
        let address = address.to_lowercase();
        let address = regex.replace_all(&address, "").to_string();

        if address.len() != 40 {
            return Err(AddressError::InvalidCharacterLength(address.len()));
        }

        let hash = to_hex_string(&keccak256(address.as_bytes()));
        let mut checksum_address = "0x".to_string();
        for c in 0..40 {
            let ch = match &hash[c..=c] {
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" => address[c..=c].to_lowercase(),
                _ => address[c..=c].to_uppercase(),
            };
            checksum_address.push_str(&ch);
        }

        Ok(EthereumAddress(checksum_address))
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wagyu_model::public_key::PublicKey;

    fn test_from_private_key(expected_address: &str, private_key: &EthereumPrivateKey) {
        let address = EthereumAddress::from_private_key(private_key, &EthereumFormat::Standard).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key(expected_address: &str, public_key: &EthereumPublicKey) {
        let address = EthereumAddress::from_public_key(public_key, &EthereumFormat::Standard).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str(expected_address: &str) {
        let address = EthereumAddress::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_to_str(expected_address: &str, address: &EthereumAddress) {
        assert_eq!(expected_address, address.to_string());
    }

    mod checksum_address {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "f89f23eaeac18252fedf81bb8318d3c111d48c19b0680dcf6e0a8d5136caf287",
                "0x9141B7539E7902872095C408BfA294435e2b8c8a",
            ),
            (
                "a93701ea343247db13466f6448ffbca658726e2b4a77530db3eca3c9250b4f0d",
                "0xa0967B1F698DC497A694FE955666D1dDd398145C",
            ),
            (
                "de61e35e2e5eb9504d52f5042126591d80144d49f74b8ced68f4959a3e8edffd",
                "0xD5d13d1dD277BB9041e560A63ee29c086D370b0A",
            ),
            (
                "56f01d5e01b6fd1cc123d8d1eae0d148e00c025b5be2ef624775f7a1b802e9c1",
                "0xc4488ebbE882fa2aF1D466CB2C8ecafE316c067a",
            ),
            (
                "363af8b4d3ff22bb0e4ffc2ff198b4b5be0316f8a507ad5fe32f021c3d1ae8ad",
                "0xF9001e6AEE6EA439D713fBbF960EbA76f4770E2B",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = EthereumPrivateKey::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = EthereumPrivateKey::from_str(private_key).unwrap();
                let public_key = EthereumPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = EthereumAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    #[test]
    fn test_checksum_address_invalid() {
        // Mismatched keypair

        let private_key = "f89f23eaeac18252fedf81bb8318d3c111d48c19b0680dcf6e0a8d5136caf287";
        let expected_address = "0xF9001e6AEE6EA439D713fBbF960EbA76f4770E2B";

        let private_key = EthereumPrivateKey::from_str(private_key).unwrap();
        let address = EthereumAddress::from_private_key(&private_key, &EthereumFormat::Standard).unwrap();
        assert_ne!(expected_address, address.to_string());

        let public_key = EthereumPublicKey::from_private_key(&private_key);
        let address = EthereumAddress::from_public_key(&public_key, &EthereumFormat::Standard).unwrap();
        assert_ne!(expected_address, address.to_string());

        // Invalid address length

        let address = "9";
        assert!(EthereumAddress::from_str(address).is_err());

        let address = "0x9";
        assert!(EthereumAddress::from_str(address).is_err());

        let address = "0x9141B7539E7902872095C408BfA294435e2b8c8";
        assert!(EthereumAddress::from_str(address).is_err());

        let address = "0x9141B7539E7902872095C408BfA294435e2b8c8a0x9141B7539E7902872095";
        assert!(EthereumAddress::from_str(address).is_err());

        let address = "0x9141B7539E7902872095C408BfA294435e2b8c8a0x9141B7539E7902872095C408BfA294435e2b8c8a";
        assert!(EthereumAddress::from_str(address).is_err());
    }
}

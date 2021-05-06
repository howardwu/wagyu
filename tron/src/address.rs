use crate::{TronNetwork, format::TronFormat};
use crate::private_key::TronPrivateKey;
use crate::public_key::TronPublicKey;
use base58::ToBase58;
use wagyu_model::{Address, AddressError, PrivateKey, crypto::checksum, to_hex_string};

use regex::Regex;
use serde::Serialize;
use std::{convert::TryFrom, fmt, marker::PhantomData, str::FromStr};
use tiny_keccak::keccak256;
use sha3::{Digest, Keccak256};

/// Represents an Tron address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash)]
pub struct TronAddress<N: TronNetwork>{
    /// The Tron address
    address: String,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: TronNetwork> Address for TronAddress<N> {
    type Format = TronFormat;
    type PrivateKey = TronPrivateKey<N>;
    type PublicKey = TronPublicKey<N>;

    /// Returns the address corresponding to the given private key.
    fn from_private_key(private_key: &Self::PrivateKey, _format: &Self::Format) -> Result<Self, AddressError> {
        Self::from_public_key(&private_key.to_public_key(), _format)
    }

    /// Returns the address corresponding to the given public key.
    fn from_public_key(public_key: &Self::PublicKey, _: &Self::Format) -> Result<Self, AddressError> {
        Ok(Self::checksum_address(public_key))
    }
}

impl<N: TronNetwork> TronAddress<N> {
    /// Returns the checksum address given a public key.
    /// Adheres to EIP-55 (https://eips.ethereum.org/EIPS/eip-55).
    pub fn checksum_address(public_key: &<Self as Address>::PublicKey) -> Self {
        let public_key = public_key.to_secp256k1_public_key().serialize().to_vec();

        // Ref: https://stackoverflow.com/questions/58782314/how-to-generate-trx-wallet-without-using-api
        let mut hasher = Keccak256::new();
        hasher.update(&public_key);
        let digest = hasher.finalize();

        let mut address = [0u8; 25];
        address[0] = N::address_prefix();
        address[1..21].copy_from_slice(&digest[digest.len() - 20..]);
        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        // println!("sum:{:?}", sum);
        // println!("public_key:{:?}", public_key);
        // println!("digest:{:?}", digest);
        // println!("address:{:?}", address);
        // println!("address_58: {}", address.to_base58());

        TronAddress{address:address.to_base58(),_network: PhantomData}
    }
}

impl<'a, N: TronNetwork> TryFrom<&'a str> for TronAddress<N> {
    type Error = AddressError;

    fn try_from(address: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(address)
    }
}

impl<N: TronNetwork> FromStr for TronAddress<N> {
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

        Ok(Self{address: checksum_address,_network: PhantomData,})
    }
}

impl<N: TronNetwork> fmt::Display for TronAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wagyu_model::public_key::PublicKey;

    fn test_from_private_key<N: TronNetwork>(
        expected_address: &str,
        private_key: &TronPrivateKey<N>,
        format: &TronFormat,
    ) {
        let address = TronAddress::from_private_key(private_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key<N: TronNetwork>(
        expected_address: &str,
        public_key: &TronPublicKey<N>,
        format: &TronFormat,
    ) {
        let address = TronAddress::from_public_key(public_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str<N: TronNetwork>(expected_address: &str, expected_format: &TronFormat) {
        let address = TronAddress::<N>::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        // assert_eq!(*expected_format, address.format);
    }

    fn test_to_str<N: TronNetwork>(expected_address: &str, address: &TronAddress<N>) {
        assert_eq!(expected_address, address.to_string());
    }

    mod checksum_address {
        use crate::{Mainnet};

        use super::*;
        type N = Mainnet;

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
                let private_key = TronPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &TronFormat::Standard);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = TronPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = TronPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &TronFormat::Standard);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &TronFormat::Standard);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = TronAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    #[test]
    fn test_checksum_address_invalid() {
        // Mismatched keypair
        use crate::{Mainnet};
        type N = Mainnet;

        let private_key = "f89f23eaeac18252fedf81bb8318d3c111d48c19b0680dcf6e0a8d5136caf287";
        let expected_address = "0xF9001e6AEE6EA439D713fBbF960EbA76f4770E2B";

        let private_key = TronPrivateKey::<N>::from_str(private_key).unwrap();
        let address = TronAddress::from_private_key(&private_key, &TronFormat::Standard).unwrap();
        assert_ne!(expected_address, address.to_string());

        let public_key = TronPublicKey::<N>::from_private_key(&private_key);
        let address = TronAddress::from_public_key(&public_key, &TronFormat::Standard).unwrap();
        assert_ne!(expected_address, address.to_string());

        // Invalid address length

        let address = "9";
        assert!(TronAddress::<N>::from_str(address).is_err());

        let address = "0x9";
        assert!(TronAddress::<N>::from_str(address).is_err());

        let address = "0x9141B7539E7902872095C408BfA294435e2b8c8";
        assert!(TronAddress::<N>::from_str(address).is_err());

        let address = "0x9141B7539E7902872095C408BfA294435e2b8c8a0x9141B7539E7902872095";
        assert!(TronAddress::<N>::from_str(address).is_err());

        let address = "0x9141B7539E7902872095C408BfA294435e2b8c8a0x9141B7539E7902872095C408BfA294435e2b8c8a";
        assert!(TronAddress::<N>::from_str(address).is_err());
    }
}

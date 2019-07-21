use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use wagu_model::{Address, AddressError, PrivateKey};

use base58_monero as base58;
use serde::Serialize;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use tiny_keccak::keccak256;

/// Represents the format of a Monero address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Standard address
    Standard,
    /// Address with payment id (8 bytes)
    Integrated,
    /// Subaddress
    Subaddress
}

impl Format {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix<N: MoneroNetwork>(&self) -> u8 {
        N::to_address_prefix(self)
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: u8) -> Result<Self, AddressError> {
        match prefix {
            18 | 24 | 53 => Ok(Format::Standard),
            19 | 25 | 54 => Ok(Format::Integrated),
            42 | 36 | 63 => Ok(Format::Subaddress),
            _ => return Err(AddressError::InvalidPrefix(vec![prefix]))
        }
    }
}

/// Represents a Monero address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroAddress<N: MoneroNetwork> {
    /// The Monero address
    pub address: String,
    /// The format of the address
    pub format: Format,
    /// PhantomData
    _network: PhantomData<N>,
}

impl <N: MoneroNetwork> Address for MoneroAddress<N> {
    type Format = Format;
    type PrivateKey = MoneroPrivateKey<N>;
    type PublicKey = MoneroPublicKey<N>;

    /// Returns the address corresponding to the given Monero private key.
    fn from_private_key(
        private_key: &Self::PrivateKey,
        format: &Self::Format
    ) -> Result<Self, AddressError> {
        Self::from_public_key(&private_key.to_public_key(), format)
    }

    /// Returns the address corresponding to the given Monero public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::generate_address(&public_key, format)
    }
}

impl <N: MoneroNetwork> MoneroAddress<N> {
    /// Returns a Monero address given the public spend key and public view key.
    pub fn generate_address(
        public_key: &MoneroPublicKey<N>,
        format: &Format
    ) -> Result<Self, AddressError> {
        let mut bytes = vec![format.to_address_prefix::<N>()];
        bytes.extend_from_slice(&public_key.spend_key);
        bytes.extend_from_slice(&public_key.view_key);

        let checksum_bytes = match format {
            Format::Standard | Format::Subaddress => &bytes[0..65],
            Format::Integrated => &bytes[0..73],
        };

        let checksum = &keccak256(checksum_bytes);
        bytes.extend_from_slice(&checksum[0..4]);

        let address = base58::encode(bytes.as_slice())?;
        Ok(Self { address, format: format.clone(), _network: PhantomData })
    }
}

impl <N: MoneroNetwork> FromStr for MoneroAddress<N> {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() != 95 && address.len() != 106 {
            return Err(AddressError::InvalidCharacterLength(address.len()))
        }
        let bytes = base58::decode(address)?;

        // Check that the network byte correspond with the correct network.
        let _ = N::from_address_prefix(bytes[0])?;
        let format = Format::from_address_prefix(bytes[0])?;

        let (checksum_bytes, checksum) = match format {
            Format::Standard | Format::Subaddress => (&bytes[0..65], &bytes[65..69]),
            Format::Integrated => (&bytes[0..73], &bytes[73..77]),
        };

        let verify_checksum = &keccak256(checksum_bytes);
        if &verify_checksum[0..4] != checksum {
            let expected = base58::encode(&verify_checksum[0..4])?;
            let found = base58::encode(checksum)?;
            return Err(AddressError::InvalidChecksum(expected, found))
        }

        let public_spend_key = hex::encode(&bytes[1..33]);
        let public_view_key = hex::encode(&bytes[33..65]);
        let public_key = MoneroPublicKey::from(public_spend_key.as_str(), public_view_key.as_str())?;

        Self::generate_address(&public_key, &format)
    }
}

impl <N: MoneroNetwork> fmt::Display for MoneroAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;
    use wagu_model::public_key::PublicKey;

    fn test_from_private_key<N: MoneroNetwork>(
        expected_address: &str,
        private_key: &MoneroPrivateKey<N>,
        format: &Format
    ) {
        let address = MoneroAddress::<N>::from_private_key(private_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key<N: MoneroNetwork>(
        expected_address: &str,
        public_key: &MoneroPublicKey<N>,
        format: &Format,
    ) {
        let address = MoneroAddress::<N>::from_public_key(public_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*format, address.format);
    }

    fn test_from_str<N: MoneroNetwork>(expected_address: &str, expected_format: &Format) {
        let address = MoneroAddress::<N>::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
    }

    fn test_to_str<N: MoneroNetwork>(expected_address: &str, address: &MoneroAddress<N>) {
        assert_eq!(expected_address, address.to_string());
    }

    mod standard_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "f6aceb9caa1d04bb3a6a3d5614a731dd58d24da957f33448fa50600c3d928404",
                "42yuCfeWRoe4aRLYS82WNXfgY1eK8XH2V4hgwPjyuAEE56M4tbxqyLATxSrKPtxxEQETnhmFxW741RMYTaM9neiWCK2uvkW"
            ),
            (
                "7130e7a7657a75590fc00c2926bbcbd252044ca2210fde0dc74a6dfdd2512501",
                "44aygzVLNx72qpYQV74zxdZt9H3bQiFba57K9Gdj118CKg7XLvyMtyA21qnzvKcFxw7zSH6yE4SaZMiTzyLzSjNT1oW4seP"
            ),
            (
                "a22b4a3418db16214f1a278e1f0b115ede224f043bc1d0596a74f9748f41b00b",
                "41yGhaRKQqXKfZYggXQn9GCz27cbKaTSTDh3dAWDh8kGD8xVAVqEhATQErgFZYVG1AASYmzuMA9pMP9V92fW71uKDv4rwyd"
            ),
            (
                "c25c2b372c49fe3056b211432da1c5f76173230215df1ab0554ecf51417e7709",
                "4AZ25p3E7zFNHXXTGpmcw1iNfnDH3YevSLXQP9yT1R4H4hghhW6ipo6TcZoq2HvJFoGLp3KoVF3bKJvbqRFVxfsi8hZvU1S"
            ),
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                "48fRSJiQSp3Da61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xTungkh5"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(seed, address)| {
                let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
                test_from_private_key(address, &private_key, &Format::Standard);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(seed, address)| {
                let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
                let public_key = MoneroPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::Standard);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &Format::Standard);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = MoneroAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }
}

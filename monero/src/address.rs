use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use crate::public_key::MoneroPublicKey;
use wagyu_model::{Address, AddressError, PrivateKey, PublicKeyError};

use base58_monero as base58;
use serde::Serialize;
use std::{convert::TryFrom, fmt, marker::PhantomData, str::FromStr};
use tiny_keccak::keccak256;

/// Represents the format of a Monero address
#[derive(Serialize, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Standard address
    Standard,
    /// Address with payment id (8 bytes)
    Integrated([u8; 8]),
    /// Subaddress
    Subaddress(u32, u32),
}

impl Format {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix<N: MoneroNetwork>(&self) -> u8 {
        N::to_address_prefix(self)
    }

    /// Returns the format of the given address.
    pub fn from_address(address: &[u8]) -> Result<Self, AddressError> {
        match address[0] {
            18 | 24 | 53 => Ok(Format::Standard),
            19 | 25 | 54 => {
                let mut data = [0u8; 8];
                data.copy_from_slice(&address[65..73]);
                Ok(Format::Integrated(data))
            }
            42 | 36 | 63 => Ok(Format::Subaddress(u32::max_value(), u32::max_value())),
            _ => return Err(AddressError::InvalidPrefix(vec![address[0]])),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Format::Standard => write!(f, "standard"),
            Format::Integrated(_) => write!(f, "integrated"),
            Format::Subaddress(major, minor) => write!(f, "subaddress({},{})", major, minor),
        }
    }
}

/// Represents a Monero address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroAddress<N: MoneroNetwork> {
    /// The Monero address
    address: String,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: MoneroNetwork> Address for MoneroAddress<N> {
    type Format = Format;
    type PrivateKey = MoneroPrivateKey<N>;
    type PublicKey = MoneroPublicKey<N>;

    /// Returns the address corresponding to the given Monero private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Result<Self, AddressError> {
        match (private_key.format(), format) {
            (Format::Standard, _) | (Format::Subaddress(_, _), Format::Subaddress(_, _)) => {
                let private_key =
                    Self::PrivateKey::from_private_spend_key(&hex::encode(private_key.to_private_spend_key()), format)?;
                Self::from_public_key(&private_key.to_public_key(), format)
            }
            (Format::Integrated(_), Format::Standard)
            | (Format::Integrated(_), Format::Integrated(_))
            | (Format::Subaddress(_, _), &Format::Standard) => {
                Self::from_public_key(&private_key.to_public_key(), format)
            }
            _ => {
                return Err(AddressError::IncompatibleFormats(
                    private_key.format().to_string(),
                    format.to_string(),
                ))
            }
        }
    }

    /// Returns the address corresponding to the given Monero public key.
    fn from_public_key(public_key: &Self::PublicKey, format: &Self::Format) -> Result<Self, AddressError> {
        Self::generate_address(&public_key, format)
    }
}

impl<N: MoneroNetwork> MoneroAddress<N> {
    /// Returns a Monero address given the public spend key and public view key.
    pub fn generate_address(public_key: &MoneroPublicKey<N>, format: &Format) -> Result<Self, AddressError> {
        let public_spend_key = match public_key.to_public_spend_key() {
            Some(key) => key,
            None => return Err(AddressError::MissingPublicKey),
        };
        let public_view_key = match public_key.to_public_view_key() {
            Some(key) => key,
            None => return Err(AddressError::MissingPublicKey),
        };

        let mut format = format;
        match (public_key.format(), format) {
            (Format::Subaddress(_, _), Format::Subaddress(major, minor))
            | (Format::Standard, Format::Subaddress(major, minor)) => {
                if *major == 0 && *minor == 0 {
                    format = &Format::Standard;
                }
            }
            (Format::Integrated(_), Format::Standard)
            | (Format::Integrated(_), Format::Integrated(_))
            | (Format::Standard, _)
            | (_, &Format::Standard) => {}
            _ => {
                return Err(AddressError::IncompatibleFormats(
                    public_key.format().to_string(),
                    format.to_string(),
                ))
            }
        };

        let mut bytes = vec![format.to_address_prefix::<N>()];
        bytes.extend_from_slice(&public_spend_key);
        bytes.extend_from_slice(&public_view_key);

        let checksum_bytes = match format {
            Format::Standard | Format::Subaddress(_, _) => &bytes[0..65],
            Format::Integrated(payment_id) => {
                bytes.extend_from_slice(payment_id);
                &bytes[0..73]
            }
        };

        let checksum = &keccak256(checksum_bytes);
        bytes.extend_from_slice(&checksum[0..4]);

        let address = base58::encode(bytes.as_slice())?;
        Ok(Self {
            address,
            _network: PhantomData,
        })
    }

    /// Returns the payment ID of a Monero integrated address, or returns `None`.
    pub fn to_payment_id(&self) -> Option<String> {
        if let Ok(format) = self.format() {
            if let Format::Integrated(payment_id) = format {
                return Some(hex::encode(payment_id));
            }
        }
        None
    }

    /// Returns the format of the Monero address.
    pub fn format(&self) -> Result<Format, AddressError> {
        Format::from_address(&base58::decode(&self.address)?)
    }

    /// Returns public spending key and public viewing key
    pub fn to_public_key(&self) -> Result<MoneroPublicKey<N>, AddressError> {
        let bytes = base58::decode(&self.address)?;
        let format = Format::from_address(&bytes)?;

        let public_spend_key = hex::encode(&bytes[1..33]);
        let public_view_key = hex::encode(&bytes[33..65]);

        Ok(MoneroPublicKey::<N>::from(&public_spend_key, &public_view_key, &format)?)
    }
}

impl<'a, N: MoneroNetwork> TryFrom<&'a str> for MoneroAddress<N> {
    type Error = AddressError;

    fn try_from(address: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(address)
    }
}

impl<N: MoneroNetwork> FromStr for MoneroAddress<N> {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() != 95 && address.len() != 106 {
            return Err(AddressError::InvalidCharacterLength(address.len()));
        }
        let bytes = base58::decode(address)?;

        // Check that the network byte correspond with the correct network.
        let _ = N::from_address_prefix(bytes[0])?;
        let format = Format::from_address(&bytes)?;

        let (checksum_bytes, checksum) = match format {
            Format::Standard | Format::Subaddress(_, _) => (&bytes[0..65], &bytes[65..69]),
            Format::Integrated(_) => (&bytes[0..73], &bytes[73..77]),
        };

        let verify_checksum = &keccak256(checksum_bytes);
        if &verify_checksum[0..4] != checksum {
            let expected = base58::encode(&verify_checksum[0..4])?;
            let found = base58::encode(checksum)?;
            return Err(AddressError::InvalidChecksum(expected, found));
        }

        let public_spend_key = hex::encode(&bytes[1..33]);
        let public_view_key = hex::encode(&bytes[33..65]);
        let public_key = MoneroPublicKey::from(public_spend_key.as_str(), public_view_key.as_str(), &format)?;

        Self::generate_address(&public_key, &format)
    }
}

impl<N: MoneroNetwork> fmt::Display for MoneroAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;
    use wagyu_model::public_key::PublicKey;

    fn test_from_private_key<N: MoneroNetwork>(
        expected_address: &str,
        private_key: &MoneroPrivateKey<N>,
        format: &Format,
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
    }

    fn test_from_str<N: MoneroNetwork>(expected_address: &str) {
        let address = MoneroAddress::<N>::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_to_str<N: MoneroNetwork>(expected_address: &str, address: &MoneroAddress<N>) {
        assert_eq!(expected_address, address.to_string());
    }

    mod standard_mainnet {
        use super::*;

        type N = Mainnet;
        const FORMAT: &Format = &Format::Standard;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "f6aceb9caa1d04bb3a6a3d5614a731dd58d24da957f33448fa50600c3d928404",
                "42yuCfeWRoe4aRLYS82WNXfgY1eK8XH2V4hgwPjyuAEE56M4tbxqyLATxSrKPtxxEQETnhmFxW741RMYTaM9neiWCK2uvkW",
            ),
            (
                "7130e7a7657a75590fc00c2926bbcbd252044ca2210fde0dc74a6dfdd2512501",
                "44aygzVLNx72qpYQV74zxdZt9H3bQiFba57K9Gdj118CKg7XLvyMtyA21qnzvKcFxw7zSH6yE4SaZMiTzyLzSjNT1oW4seP",
            ),
            (
                "a22b4a3418db16214f1a278e1f0b115ede224f043bc1d0596a74f9748f41b00b",
                "41yGhaRKQqXKfZYggXQn9GCz27cbKaTSTDh3dAWDh8kGD8xVAVqEhATQErgFZYVG1AASYmzuMA9pMP9V92fW71uKDv4rwyd",
            ),
            (
                "c25c2b372c49fe3056b211432da1c5f76173230215df1ab0554ecf51417e7709",
                "4AZ25p3E7zFNHXXTGpmcw1iNfnDH3YevSLXQP9yT1R4H4hghhW6ipo6TcZoq2HvJFoGLp3KoVF3bKJvbqRFVxfsi8hZvU1S",
            ),
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                "48fRSJiQSp3Da61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xTungkh5",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(seed, address)| {
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, FORMAT).unwrap();
                test_from_private_key(address, &private_key, FORMAT);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(seed, address)| {
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, FORMAT).unwrap();
                let public_key = MoneroPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, FORMAT);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address);
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

    mod integrated_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "f6aceb9caa1d04bb3a6a3d5614a731dd58d24da957f33448fa50600c3d928404",
                "67feb00802e01236",
                "4CgaDUU135A4aRLYS82WNXfgY1eK8XH2V4hgwPjyuAEE56M4tbxqyLATxSrKPtxxEQETnhmFxW741RMYTaM9neiWHo4qiLKX62u76x816i"
            ),
            (
                "7130e7a7657a75590fc00c2926bbcbd252044ca2210fde0dc74a6dfdd2512501",
                "764cdf210f82625a",
                "4EHehoJpzDd2qpYQV74zxdZt9H3bQiFba57K9Gdj118CKg7XLvyMtyA21qnzvKcFxw7zSH6yE4SaZMiTzyLzSjNT2FPj5adNgMwBBKmfsx"
            ),
            (
                "a22b4a3418db16214f1a278e1f0b115ede224f043bc1d0596a74f9748f41b00b",
                "f152bf559bf7a826",
                "4BfwiPEp273KfZYggXQn9GCz27cbKaTSTDh3dAWDh8kGD8xVAVqEhATQErgFZYVG1AASYmzuMA9pMP9V92fW71uKLE66biF8PTM5MdHfjw"
            ),
            (
                "c25c2b372c49fe3056b211432da1c5f76173230215df1ab0554ecf51417e7709",
                "81eadd72620de7bd",
                "4LFh6crijFmNHXXTGpmcw1iNfnDH3YevSLXQP9yT1R4H4hghhW6ipo6TcZoq2HvJFoGLp3KoVF3bKJvbqRFVxfsiCTcHtcJHdRxNQqq9ui"
            ),
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                "ad03f0d9eb520086",
                "4JN6T7Xu45ZDa61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xgvTNQWTCJbqGCcEBX3"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(seed, payment_id, address)| {
                let mut payment_id_bytes = [0u8; 8];
                payment_id_bytes.copy_from_slice(&hex::decode(payment_id).unwrap());
                let format = &Format::Integrated(payment_id_bytes);
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, format).unwrap();
                test_from_private_key(address, &private_key, format);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(seed, payment_id, address)| {
                let mut payment_id_bytes = [0u8; 8];
                payment_id_bytes.copy_from_slice(&hex::decode(payment_id).unwrap());
                let format = &Format::Integrated(payment_id_bytes);
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, format).unwrap();
                let public_key = MoneroPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, format);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, _, address)| {
                test_from_str::<N>(address);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, _, expected_address)| {
                let address = MoneroAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod subaddress_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, u32, u32, &str); 5] = [
            (
                "f6aceb9caa1d04bb3a6a3d5614a731dd58d24da957f33448fa50600c3d928404",
                0,
                0,
                "42yuCfeWRoe4aRLYS82WNXfgY1eK8XH2V4hgwPjyuAEE56M4tbxqyLATxSrKPtxxEQETnhmFxW741RMYTaM9neiWCK2uvkW",
            ),
            (
                "7130e7a7657a75590fc00c2926bbcbd252044ca2210fde0dc74a6dfdd2512501",
                0,
                1,
                "83NfRiAk5AiBZDyTjGDejpap8VJDgspsyQhHfGZAVATpfPwaJ9SXRcHEkTC8chu8gEcrudMymLT8dFKkidrqTEVRKApoPSx",
            ),
            (
                "a22b4a3418db16214f1a278e1f0b115ede224f043bc1d0596a74f9748f41b00b",
                1,
                100,
                "87DrKYY4cXidB8g9kB9pS6dH3xvySXRg71Abpy2nGHemGX7sKA2kdFT8MgReY8jbdMaESqJU8XeAzbFqYdUREQPtKC3yTYS",
            ),
            (
                "c25c2b372c49fe3056b211432da1c5f76173230215df1ab0554ecf51417e7709",
                25000,
                0,
                "8AypGY3tMu49YQqZ49cFUjBoywJJ72r6R9xmjq77jLHTD8GxyV3AKogahHNhNWZDWKZPxbdaDASwT5axCkmwhCaYH8DYADx",
            ),
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                5000,
                123456789,
                "84Enuwpd5cMhvXowv12wdEL7Y7u57fPSAHkjM6pBjHCDf4M3mkXQkcbiLmBFJYXJ1JKLTP1RyJMEU5iUZ5dLfh5GRJYBzdy",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(seed, major, minor, address)| {
                let format = &Format::Subaddress(*major, *minor);
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, format).unwrap();
                test_from_private_key(address, &private_key, format);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(seed, major, minor, address)| {
                let format = &Format::Subaddress(*major, *minor);
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, format).unwrap();
                let public_key = MoneroPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, format);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, _, _, address)| {
                test_from_str::<N>(address);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, _, _, expected_address)| {
                let address = MoneroAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod invalid_address {
        use super::*;
        type N = Mainnet;

        #[test]
        fn test_invalid_from_str() {
            let address_str = "";
            let address = MoneroAddress::<N>::from_str(address_str);
            assert!(address.is_err());

            let address_str = "48XeJoEK8swMyYwNaLw";
            let address = MoneroAddress::<N>::from_str(address_str);
            assert!(address.is_err());

            let address_str = "48XeJoEK8swMyYwNaLwYDfPTD9YkeyBQnLhspCWyipPShsJ8SGhCHEJdD6y93S31mmEJTmPjM";
            let address = MoneroAddress::<N>::from_str(address_str);
            assert!(address.is_err());

            let address_str =
                "11XeJoEK8swMyYwNaLwYDfPTD9YkeyBQnLhspCWyipPShsJ8SGhCHEJdD6y93S31mmEJTmPjMteR4Hky1vDHV2xmDrctPv3";
            let address = MoneroAddress::<N>::from_str(address_str);
            assert!(address.is_err());

            let address_str =
                "28XeJoEK8swMyYwNaLwYDfPTD9YkeyBQnLhspCWyipPShsJ8SGhCHEJdD6y93S31mmEJTmPjMteR4Hky1vDHV2xmDrctPv3";
            let address = MoneroAddress::<N>::from_str(address_str);
            assert!(address.is_err());
        }

        #[test]
        fn test_invalid_from_address() {
            let address = base58::decode(
                "11XeJoEK8swMyYwNaLwYDfPTD9YkeyBQnLhspCWyipPShsJ8SGhCHEJdD6y93S31mmEJTmPjMteR4Hky1vDHV2xmDrctPv3",
            )
            .unwrap();
            let address = Format::from_address(&address);
            assert!(address.is_err());

            let address = base58::decode(
                "28XeJoEK8swMyYwNaLwYDfPTD9YkeyBQnLhspCWyipPShsJ8SGhCHEJdD6y93S31mmEJTmPjMteR4Hky1vDHV2xmDrctPv3",
            )
            .unwrap();
            let address = Format::from_address(&address);
            assert!(address.is_err());

            let address = base58::decode(
                "eeeeJoEK8swMyYwNaLwYDfPTD9YkeyBQnLhspCWyipPShsJ8SGhCHEJdD6y93S31mmEJTmPjMteR4Hky1vDHV2xmDrctPv3",
            )
            .unwrap();
            let address = Format::from_address(&address);
            assert!(address.is_err());
        }

        #[test]
        fn test_invalid_from_private_key() {
            let seed = "c4ea94e090f99fb9adabddae893aecc00f575ff8a491086215c19ccd7f5eb102";
            let private_key = MoneroPrivateKey::<N>::from_seed(seed, &Format::Subaddress(0, 1)).unwrap();
            let address = MoneroAddress::<N>::from_private_key(&private_key, &Format::Integrated([0u8; 8]));
            assert!(address.is_err());

            let seed = "e410c79f35e1d28ecc1838c73506f3500e6726b36764c5bae6576bc0d0e8610f";
            let private_key = MoneroPrivateKey::<N>::from_seed(seed, &Format::Subaddress(100, 100)).unwrap();
            let address = MoneroAddress::<N>::from_private_key(&private_key, &Format::Integrated([1u8; 8]));
            assert!(address.is_err());

            let seed = "7b1502b83bdc3b97dc2bfb77e642a544444379ef5a675f17120ff055de9dc230";
            let private_key = MoneroPrivateKey::<N>::from_seed(seed, &Format::Integrated([0u8; 8])).unwrap();
            let address = MoneroAddress::<N>::from_private_key(&private_key, &Format::Subaddress(0, 1));
            assert!(address.is_err());

            let seed = "6704781ff5938ea507f2b4615efa9b1cbc98a04c1ea616037b1f032a0d29a70f";
            let private_key =
                MoneroPrivateKey::<N>::from_seed(seed, &Format::Integrated([u8::max_value(); 8])).unwrap();
            let address = MoneroAddress::<N>::from_private_key(&private_key, &Format::Subaddress(100, 0));
            assert!(address.is_err());
        }

        #[test]
        fn test_invalid_from_public_key() {
            let seed = "c4ea94e090f99fb9adabddae893aecc00f575ff8a491086215c19ccd7f5eb102";
            let private_key = MoneroPrivateKey::<N>::from_seed(seed, &Format::Subaddress(0, 1)).unwrap();
            let public_key = MoneroPublicKey::<N>::from_private_key(&private_key);
            let address = MoneroAddress::<N>::from_public_key(&public_key, &Format::Integrated([0u8; 8]));
            assert!(address.is_err());

            let seed = "e410c79f35e1d28ecc1838c73506f3500e6726b36764c5bae6576bc0d0e8610f";
            let private_key = MoneroPrivateKey::<N>::from_seed(seed, &Format::Subaddress(100, 100)).unwrap();
            let public_key = MoneroPublicKey::<N>::from_private_key(&private_key);
            let address = MoneroAddress::<N>::from_public_key(&public_key, &Format::Integrated([1u8; 8]));
            assert!(address.is_err());

            let seed = "7b1502b83bdc3b97dc2bfb77e642a544444379ef5a675f17120ff055de9dc230";
            let private_key = MoneroPrivateKey::<N>::from_seed(seed, &Format::Integrated([0u8; 8])).unwrap();
            let public_key = MoneroPublicKey::<N>::from_private_key(&private_key);
            let address = MoneroAddress::<N>::from_public_key(&public_key, &Format::Subaddress(0, 1));
            assert!(address.is_err());

            let seed = "6704781ff5938ea507f2b4615efa9b1cbc98a04c1ea616037b1f032a0d29a70f";
            let private_key =
                MoneroPrivateKey::<N>::from_seed(seed, &Format::Integrated([u8::max_value(); 8])).unwrap();
            let public_key = MoneroPublicKey::<N>::from_private_key(&private_key);
            let address = MoneroAddress::<N>::from_public_key(&public_key, &Format::Subaddress(100, 0));
            assert!(address.is_err());
        }
    }
}

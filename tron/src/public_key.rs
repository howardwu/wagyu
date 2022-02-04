use crate::{TronNetwork, address::TronAddress};
use crate::format::TronFormat;
use crate::private_key::TronPrivateKey;
use wagyu_model::{Address, AddressError, PublicKey, PublicKeyError};

use secp256k1;
use std::{fmt, fmt::Display, marker::PhantomData, str::FromStr};

/// Represents an Tron public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TronPublicKey<N: TronNetwork> {
    /// The ECDSA public key
    public_key: secp256k1::PublicKey,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: TronNetwork> PublicKey for TronPublicKey<N> {
    type Address = TronAddress<N>;
    type Format = TronFormat;
    type PrivateKey = TronPrivateKey<N>;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        Self{public_key: secp256k1::PublicKey::from_secret_key(&private_key.to_secp256k1_secret_key()), _network: PhantomData}
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        TronAddress::from_public_key(self, _format)
    }
}

impl<N: TronNetwork> TronPublicKey<N> {
    /// Returns a public key given a secp256k1 public key.
    pub fn from_secp256k1_public_key(public_key: secp256k1::PublicKey) -> Self {
        Self{public_key: public_key, _network: PhantomData}
    }

    /// Returns the secp256k1 public key of the public key
    pub fn to_secp256k1_public_key(&self) -> secp256k1::PublicKey {
        self.public_key.clone()
    }
}

impl<N: TronNetwork> FromStr for TronPublicKey<N> {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            public_key: secp256k1::PublicKey::parse_slice(&hex::decode(public_key)?, None)?,
            _network: PhantomData,
        })
    }
}

impl<N: TronNetwork> Display for TronPublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // if self.compressed {
        //     for s in &self.public_key.serialize_compressed()[..] {
        //         write!(f, "{:02x}", s)?;
        //     }
        // } else {
        //     for s in &self.public_key.serialize()[..] {
        //         write!(f, "{:02x}", s)?;
        //     }
        // }
        for s in &self.public_key.serialize()[..] {
            write!(f, "{:02x}", s)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_private_key<N: TronNetwork>(
        expected_public_key: &TronPublicKey<N>,
        private_key: &TronPrivateKey<N>,
    ) {
        let public_key = TronPublicKey::from_private_key(private_key);
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address<N: TronNetwork>(
        expected_address: &TronAddress<N>,
        expected_format: &TronFormat,
        public_key: &TronPublicKey<N>,
    ) {
        let address = public_key.to_address(expected_format).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_str<N: TronNetwork>(
        expected_public_key: &str,
        expected_address: &str,
        // expected_compressed: bool,
        expected_format: &TronFormat,
    ) {
        let public_key = TronPublicKey::<N>::from_str(expected_public_key).unwrap();
        let address = public_key.to_address(expected_format).unwrap();
        assert_eq!(expected_public_key, public_key.to_string());
        // assert_eq!(expected_compressed, public_key.compressed);
        assert_eq!(expected_address, address.to_string());
        // assert_eq!(*expected_format, address.format());
    }

    fn test_to_str<N: TronNetwork>(expected_public_key: &str, public_key: &TronPublicKey<N>) {
        assert_eq!(expected_public_key, public_key.to_string());
    }

    mod checksum_address {
        use crate::Mainnet;

        use super::*;
        type N = Mainnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "2f46188bd601ece2a4446fa31de9419ee9baabf5305d65a5a7aea8badee27a5a",
                "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721c",
                "0x9Ed0C5817aE96Cb886BF74EB02B238De682e9B07"
            ),
            (
                "d96c4c30bbabde58653e4fb4f4d97d064c70e300a37ab8780a8ecc15220423fb",
                "bfe0746c85802c3ca1c2d5e4f4d23fb8321b8b1009af67855cc9a4aed8285567d7045bb700e27d5e33572ae5d84a8d1e11bb134f6f14f37ffcb2fa73f7c6b0ac",
                "0xBc90633A78dA594ace8e25AAA3517F924C76099d"
            ),
            (
                "c677a1215eebd35d20337d8896ee6579c78f41f93946b17c8d4ccb772c25cde4",
                "ff3e50efb509efd0d18ff9074bc8b253419d2437e0c1e81661c1ba419f877162eed685d80bdd3b33adde4ff2a0946dd97460f126992064059a129e2a7172d566",
                "0xA99E404A60ab8561F7c844529F735A88D7A61C5A"
            ),
            (
                "b681e5bd4ddffefe1a691fe7c6375775c11992b9a25e4f9e3f235eb054d49343",
                "d9ed72afa68a9732df005df2dbbfb2abcad050579bd8dfeb32389d0f1e492d130ca33f9e71345d558da5859026fee86c03be685f95a4c8ddc55e048c5ff8b398",
                "0x28826C9f713c96ee63e59Ed9220c77b021FAfC3e"
            ),
            (
                "da5d359af6827e76e0a1b71c75c375f0d33f63bae4fd551d81ee10faa34e33e9",
                "0b752d5e89126b62a99edfe40a4cbd9122cfb04257a28d225858d38bc92a0e1517e797e9029e810b329afa32a1d46268e84eb10c700314b0059f506130d1e9e6",
                "0x9eC59170674DbEfeF40efE2ED03175b39fCA921a"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = TronPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = TronPrivateKey::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = TronAddress::<N>::from_str(address).unwrap();
                let public_key = TronPublicKey::from_str(&public_key).unwrap();
                test_to_address(&address, &TronFormat::Standard, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, &TronFormat::Standard);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = TronPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
        }
    }

    #[test]
    fn test_checksum_address_invalid() {
        use crate::Mainnet;

        use super::*;
        type N = Mainnet;
        // Invalid public key length

        let public_key = "0";
        assert!(TronPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b014";
        assert!(TronPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721";
        assert!(TronPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721c06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f3593";
        assert!(TronPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721c06d68e391c6961fceb5d8c5ad8ee5c6346db24df9dae61c9c0b0142409760451d982c0f35931f33e57adfc4f11bdf1946be2d75d6ecc925e8d22f319c71a721c";
        assert!(TronPublicKey::<N>::from_str(public_key).is_err());
    }
}

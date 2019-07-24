use crate::address::{Format, MoneroAddress};
use crate::network::MoneroNetwork;
use crate::public_key::MoneroPublicKey;
use wagu_model::{Address, AddressError, PrivateKey, PrivateKeyError, PublicKey};

use byteorder::{LittleEndian, WriteBytesExt};
use curve25519_dalek::{scalar::Scalar};
use hex;
use rand::Rng;
use rand::rngs::OsRng;
use std::{fmt, fmt::Display};
use std::marker::PhantomData;
use std::str::FromStr;
use tiny_keccak::keccak256;

/// Represents a Monero private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MoneroPrivateKey<N: MoneroNetwork> {
    /// The private spending key
    pub spend_key: [u8; 32],
    /// The private viewing key
    pub view_key: [u8; 32],
    /// Optional
    pub subaddress_view_key: Option<[u8;32]>,
    /// PhantomData
    _network: PhantomData<N>,
}

impl <N: MoneroNetwork> PrivateKey for MoneroPrivateKey<N> {
    type Address = MoneroAddress<N>;
    type Format = Format;
    type PublicKey = MoneroPublicKey<N>;

    /// Returns a randomly-generated Monero private key.
    fn new() -> Result<Self, PrivateKeyError> {
        let mut random = [0u8; 32];
        OsRng.try_fill(&mut random)?;
        Self::from_seed(hex::encode(random).as_str())
    }

    /// Returns the public key of the corresponding Monero private key.
    fn to_public_key(&self) -> Self::PublicKey {
        MoneroPublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Monero private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        MoneroAddress::from_private_key(self, format)
    }
}

impl <N: MoneroNetwork> MoneroPrivateKey<N> {
    /// Returns a private key given seed bytes.
    pub fn from_seed(seed: &str) -> Result<Self, PrivateKeyError> {
        let seed = hex::decode(seed)?;
        if seed.len() != 32 {
            return Err(PrivateKeyError::InvalidByteLength(seed.len()))
        }

        let mut s = [0u8; 32];
        s.copy_from_slice(seed.as_slice());

        let spend_key = Scalar::from_bytes_mod_order(s).to_bytes();
        Ok(Self {
            spend_key,
            view_key: Scalar::from_bytes_mod_order(keccak256(&spend_key)).to_bytes(),
            subaddress_view_key: None,
            _network: PhantomData
        })
    }

    /// Returns a private key given a private spend key.
    pub fn from_private_spend_key(
        private_spend_key: &str,
    ) -> Result<Self, PrivateKeyError> {
        let key = hex::decode(private_spend_key)?;
        if key.len() != 32 {
            return Err(PrivateKeyError::InvalidByteLength(key.len()))
        }

        let mut spend_key = [0u8; 32];
        spend_key.copy_from_slice(key.as_slice());

        Ok(Self {
            spend_key,
            view_key: Scalar::from_bytes_mod_order(keccak256(&spend_key)).to_bytes(),
            subaddress_view_key: None,
            _network: PhantomData
        })
    }

    /// Generate a subaddress private view key - Hs("SubAddr" || a || account_index || subaddress_index_within_account)
    pub fn generate_subaddress_private_view_key(&mut self, major: u32, minor: u32) -> Result<[u8; 32], PrivateKeyError>{
        if major == 0 && minor == 0 {
            self.subaddress_view_key = None;
            Ok([0u8; 32])
        } else {
            let mut major_index: Vec<u8> = Vec::new();
            let mut minor_index: Vec<u8> = Vec::new();

            major_index.write_u32::<LittleEndian>(major)?;
            minor_index.write_u32::<LittleEndian>(minor)?;

            let mut derivation: Vec<u8> = b"SubAddr\x00"[..].into();
            derivation.extend(&self.view_key);
            derivation.extend(&major_index);
            derivation.extend(&minor_index);

            let subaddress_view_key = Scalar::from_bytes_mod_order(keccak256(&derivation)).to_bytes();
            self.subaddress_view_key = Some(subaddress_view_key);
            Ok(subaddress_view_key)
        }
    }
}

impl <N: MoneroNetwork> FromStr for MoneroPrivateKey<N> {
    type Err = PrivateKeyError;
    // TODO (howardwu): Add parsing of mainnet or testnet as an option.
    fn from_str(seed: &str) -> Result<Self, PrivateKeyError> {
        Self::from_seed(seed)
    }
}

impl <N: MoneroNetwork> Display for MoneroPrivateKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(")?;
        for byte in &self.spend_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ", ")?;
        for byte in &self.view_key {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;

    fn test_to_public_key<N: MoneroNetwork>(
        expected_public_key: &MoneroPublicKey<N>,
        private_key: &MoneroPrivateKey<N>
    ) {
        let public_key = private_key.to_public_key();
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address<N: MoneroNetwork>(
        expected_address: &MoneroAddress<N>,
        expected_format: &Format,
        private_key: &MoneroPrivateKey<N>
    ) {
        let address = private_key.to_address(expected_format).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_seed<N: MoneroNetwork>(
        expected_private_spend_key: &str,
        expected_private_view_key: &str,
        expected_address: &str,
        expected_format: &Format,
        seed: &str,
    ) {
        let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
        assert_eq!(expected_private_spend_key, hex::encode(private_key.spend_key));
        assert_eq!(expected_private_view_key, hex::encode(private_key.view_key));
        assert_eq!(expected_address, private_key.to_address(expected_format).unwrap().to_string());
    }

    fn test_from_private_spend_key<N: MoneroNetwork>(
        expected_private_view_key: &str,
        expected_address: &str,
        expected_format: &Format,
        private_spend_key: &str,
    ) {
        let private_key = MoneroPrivateKey::<N>::from_private_spend_key(private_spend_key).unwrap();
        assert_eq!(private_spend_key, hex::encode(private_key.spend_key));
        assert_eq!(expected_private_view_key, hex::encode(private_key.view_key));
        assert_eq!(expected_address, private_key.to_address(expected_format).unwrap().to_string());
    }

    fn test_to_str<N: MoneroNetwork>(
        expected_private_spend_key: &str,
        expected_private_view_key: &str,
        private_key: &MoneroPrivateKey<N>
    ) {
        assert_eq!(format!("({}, {})", expected_private_spend_key, expected_private_view_key), private_key.to_string());
    }

    mod standard_mainnet {
        use super::*;

        type N = Mainnet;

        // (seed, (private_spend_key, private_view_key), (public_spend_key, public_view_key), address)
        const KEYPAIRS: [(&str, (&str, &str), (&str, &str), &str); 5] = [
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                ("3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600", "5177c436f032666c572df97ab591cc6ac2da96ab6818a2f38d72b430aebbdc0a"),
                ("b9c5610a07f4344b27625155614fb1341dd0392c68482f101b820bc1e2b908e5", "0df7c88054ae3c5f75c364257d064f42d660e6ea1184bd2a3af0d7455cb4e9ee"),
                "48fRSJiQSp3Da61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xTungkh5"
            ),
            (
                "a90aaafd9d8112848ca44b3230fbda22974b0ba1b0e74870bda8825d6ff60b06",
                ("a90aaafd9d8112848ca44b3230fbda22974b0ba1b0e74870bda8825d6ff60b06", "498a9d7cc43b05eee500a60901c1007990ad5c0e637d72d5f6f5dfd86f50ec09"),
                ("07ab31ccf46bda1d9dee0344b03cf689fb1f9302bd1f13fe52048e73b258f1e1", "cec2f7e6079ff911e6a4cc00942f18fa8abb0d247b27c41a785035136ff7412d"),
                "41uxs7goiMo5xKdNQosRUhQ5b7EyyY6SWjYE8D1BLuoWemcoD3wWkpY3zfNpcgPtNjiua5wPQoB395Rnvy159VnY67GHR9b"
            ),
            (
                "cff04d7e8db3f7910f6044a61e079a6e006b878f1e31596441951148be3f030c",
                ("cff04d7e8db3f7910f6044a61e079a6e006b878f1e31596441951148be3f030c", "539e8ee06b61cb4a6ee3875b18b10d8ce113c93d3b766af7d7ca24dc2b3f3c01"),
                ("70dddd449b5011e08876d307a76bf2d6bbd04b2cff4f7e3e5fde3d352065b5a3", "087fd0571b27542ff94e3cd88dfacf1f5c6d5736feec0a8e36e038107eed0741"),
                "45uBYxmi472eZFce75VAobcvBkZW1jGhbBS7RBWSSp9rUGdKm6gYc5R92QaGLesxNJ6FF167AWws7Qnf8aayDvkN8Q5CqEU"
            ),
            (
                "3de1ab3ee61116692a18e2cbd0f4be70e19200262b9426ef2ea3c990d0068700",
                ("3de1ab3ee61116692a18e2cbd0f4be70e19200262b9426ef2ea3c990d0068700", "394c84948bd577a8cb1dffa4cbccb51f65ac5439f8e256b0a0374b320bc99802"),
                ("72d2c60260247ef57c875c1fbd51352368731d38f32cb050fd2ab27b9cb54d54", "891a9b16a83efa53f56bac0412fe2cdfdfbfe6d8fbaf879cbc8fb28ec3a28553"),
                "45yUzNd6Kzdi4XWQCPhauA6vW7nXkwDNXEYhFwy7c2NGF96rFUscKE9F3WFW3i6ixTeSrnpfMxgdCTDYP4sCcBkxANMA62p"
            ),
            (
                "7dc2f3340b8f41b6f5166235011d1fa58e7f2d32d761a56dc3e618255692c704",
                ("7dc2f3340b8f41b6f5166235011d1fa58e7f2d32d761a56dc3e618255692c704", "5a224a898a42d48025efccfb14c2062610ec95ddfe02c764e6ababe1ed44780d"),
                ("ccfc5403e256475e5824310864cff02da9badeeeae09c7a78baf920f89332b20", "c1b9ecd218547d81c3a15a0c0c6b02f0a56def8748f39eef054397a9df27f5c9"),
                "49PevuALZP4GnFxcmJLwt38dzKtg35WSiV2QMYfcQ6KU6UnKmkcUngCNhskr4Pu4ZwhFa3NY1jyRXgyoLPWBK4gcPmyURJg"
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(seed, _, (public_spend_key, public_view_key), _)| {
                let public_key = MoneroPublicKey::<N>::from(public_spend_key, public_view_key).unwrap();
                let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(seed, _, _, address)| {
                let address = MoneroAddress::<N>::from_str(address).unwrap();
                let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
                test_to_address(&address, &Format::Standard, &private_key);
            });
        }

        #[test]
        fn from_seed() {
            KEYPAIRS.iter().for_each(|(seed, (private_spend_key, private_view_key), _, address)| {
                test_from_seed::<N>(
                    private_spend_key,
                    private_view_key,
                    address,
                    &Format::Standard,
                    seed);
            });
        }

        #[test]
        fn from_private_spend_key() {
            KEYPAIRS.iter().for_each(|(_, (private_spend_key, private_view_key), _, address)| {
                test_from_private_spend_key::<N>(
                    private_view_key,
                    address,
                    &Format::Standard,
                    private_spend_key);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(seed, (private_spend_key, private_view_key), _, _)| {
                let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
                test_to_str(private_spend_key, private_view_key, &private_key);
            });
        }
    }

    mod integrated_mainnet {
        use super::*;
        use crate::PaymentId;

        type N = Mainnet;

        // (seed, (private_spend_key, private_view_key), (public_spend_key, public_view_key), payment_id, address)
        const KEYPAIRS: [(&str, (&str, &str), (&str, &str), &str, &str); 5] = [
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                ("3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600", "5177c436f032666c572df97ab591cc6ac2da96ab6818a2f38d72b430aebbdc0a"),
                ("b9c5610a07f4344b27625155614fb1341dd0392c68482f101b820bc1e2b908e5", "0df7c88054ae3c5f75c364257d064f42d660e6ea1184bd2a3af0d7455cb4e9ee"),
                "b5a615cb2a72673e",
                "4JN6T7Xu45ZDa61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xgvnLzaB9RDG84J2X9m"
            ),
            (
                "a90aaafd9d8112848ca44b3230fbda22974b0ba1b0e74870bda8825d6ff60b06",
                ("a90aaafd9d8112848ca44b3230fbda22974b0ba1b0e74870bda8825d6ff60b06", "498a9d7cc43b05eee500a60901c1007990ad5c0e637d72d5f6f5dfd86f50ec09"),
                ("07ab31ccf46bda1d9dee0344b03cf689fb1f9302bd1f13fe52048e73b258f1e1", "cec2f7e6079ff911e6a4cc00942f18fa8abb0d247b27c41a785035136ff7412d"),
                "7c0aeaeb4ee96703",
                "4BcdsvWJKdK5xKdNQosRUhQ5b7EyyY6SWjYE8D1BLuoWemcoD3wWkpY3zfNpcgPtNjiua5wPQoB395Rnvy159VnY8cFueaJekH41QafhiH"
            ),
            (
                "cff04d7e8db3f7910f6044a61e079a6e006b878f1e31596441951148be3f030c",
                ("cff04d7e8db3f7910f6044a61e079a6e006b878f1e31596441951148be3f030c", "539e8ee06b61cb4a6ee3875b18b10d8ce113c93d3b766af7d7ca24dc2b3f3c01"),
                ("70dddd449b5011e08876d307a76bf2d6bbd04b2cff4f7e3e5fde3d352065b5a3", "087fd0571b27542ff94e3cd88dfacf1f5c6d5736feec0a8e36e038107eed0741"),
                "937e038fe6e1e6e4",
                "4FbrZmbCfNYeZFce75VAobcvBkZW1jGhbBS7RBWSSp9rUGdKm6gYc5R92QaGLesxNJ6FF167AWws7Qnf8aayDvkNByAuHyxCV8ySn5jGLW"
            ),
            (
                "3de1ab3ee61116692a18e2cbd0f4be70e19200262b9426ef2ea3c990d0068700",
                ("3de1ab3ee61116692a18e2cbd0f4be70e19200262b9426ef2ea3c990d0068700", "394c84948bd577a8cb1dffa4cbccb51f65ac5439f8e256b0a0374b320bc99802"),
                ("72d2c60260247ef57c875c1fbd51352368731d38f32cb050fd2ab27b9cb54d54", "891a9b16a83efa53f56bac0412fe2cdfdfbfe6d8fbaf879cbc8fb28ec3a28553"),
                "e0e91e3812ac029a",
                "4FgA1BSawG9i4XWQCPhauA6vW7nXkwDNXEYhFwy7c2NGF96rFUscKE9F3WFW3i6ixTeSrnpfMxgdCTDYP4sCcBkxF2jAswf7qPwJSsGpUd"
            ),
            (
                "7dc2f3340b8f41b6f5166235011d1fa58e7f2d32d761a56dc3e618255692c704",
                ("7dc2f3340b8f41b6f5166235011d1fa58e7f2d32d761a56dc3e618255692c704", "5a224a898a42d48025efccfb14c2062610ec95ddfe02c764e6ababe1ed44780d"),
                ("ccfc5403e256475e5824310864cff02da9badeeeae09c7a78baf920f89332b20", "c1b9ecd218547d81c3a15a0c0c6b02f0a56def8748f39eef054397a9df27f5c9"),
                "fa462408bb977079",
                "4K6KwhyqAeaGnFxcmJLwt38dzKtg35WSiV2QMYfcQ6KU6UnKmkcUngCNhskr4Pu4ZwhFa3NY1jyRXgyoLPWBK4gcanSHrfVBZ3mEfcpm4A"
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(seed, _, (public_spend_key, public_view_key), _, _)| {
                let public_key = MoneroPublicKey::<N>::from(public_spend_key, public_view_key).unwrap();
                let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(seed, _, _, payment_id, address)| {
                let address = MoneroAddress::<N>::from_str(address).unwrap();
                let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
                let mut data = [0u8; 8];
                data.copy_from_slice(&hex::decode(payment_id).unwrap()[0..8]);
                test_to_address(&address, &Format::Integrated(PaymentId { data }), &private_key);
            });
        }

        #[test]
        fn from_seed() {
            KEYPAIRS.iter().for_each(|(seed, (private_spend_key, private_view_key), _, payment_id, address)| {
                let mut data = [0u8; 8];
                data.copy_from_slice(&hex::decode(payment_id).unwrap()[0..8]);
                test_from_seed::<N>(
                    private_spend_key,
                    private_view_key,
                    address,
                    &Format::Integrated(PaymentId { data }),
                    seed);
            });
        }

        #[test]
        fn from_private_spend_key() {
            KEYPAIRS.iter().for_each(|(_, (private_spend_key, private_view_key), _, payment_id, address)| {
                let mut data = [0u8; 8];
                data.copy_from_slice(&hex::decode(payment_id).unwrap()[0..8]);
                test_from_private_spend_key::<N>(
                    private_view_key,
                    address,
                    &Format::Integrated(PaymentId { data }),
                    private_spend_key);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(seed, (private_spend_key, private_view_key), _, _, _)| {
                let private_key = MoneroPrivateKey::<N>::from_seed(seed).unwrap();
                test_to_str(private_spend_key, private_view_key, &private_key);
            });
        }
    }
}

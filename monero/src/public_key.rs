use crate::address::{Format, MoneroAddress};
use crate::network::MoneroNetwork;
use crate::private_key::MoneroPrivateKey;
use wagu_model::{Address, AddressError, PublicKey, PublicKeyError};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use std::{fmt, fmt::Display};
use std::marker::PhantomData;
use std::str::FromStr;

/// Represents a Monero public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoneroPublicKey<N: MoneroNetwork> {
    /// The public spending key
    pub spend_key: [u8; 32],
    /// The public viewing key
    pub view_key: [u8; 32],
    /// PhantomData
    _network: PhantomData<N>
}

impl <N: MoneroNetwork> PublicKey for MoneroPublicKey<N> {
    type Address = MoneroAddress<N>;
    type Format = Format;
    type PrivateKey = MoneroPrivateKey<N>;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        let spend_key = MoneroPublicKey::scalar_mul_by_b_compressed(&private_key.spend_key);
        let view_key = MoneroPublicKey::scalar_mul_by_b_compressed(&private_key.view_key);
        Self { spend_key, view_key, _network: PhantomData }
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        MoneroAddress::from_public_key(self, format)
    }
}

impl <N: MoneroNetwork> MoneroPublicKey<N> {
    /// Returns a Monero public key given a public spend key and public view key.
    pub fn from(public_spend_key: &str, public_view_key: &str) -> Result<Self, PublicKeyError> {

        let public_spend_key = hex::decode(public_spend_key)?;
        if public_spend_key.len() != 32 {
            return Err(PublicKeyError::InvalidByteLength(public_spend_key.len()))
        }

        let public_view_key = hex::decode(public_view_key)?;
        if public_view_key.len() != 32 {
            return Err(PublicKeyError::InvalidByteLength(public_view_key.len()))
        }

        let mut spend_key = [0u8; 32];
        spend_key.copy_from_slice(public_spend_key.as_slice());

        let mut view_key = [0u8; 32];
        view_key.copy_from_slice(public_view_key.as_slice());

        Ok(Self { spend_key, view_key })
    }

    fn scalar_mul_by_b_compressed(bits: &[u8; 32]) -> [u8; 32] {
        let point = &Scalar::from_bits(*bits) * &ED25519_BASEPOINT_TABLE;
        let compressed = *point.compress().as_bytes();
        compressed
    }
}

impl <N: MoneroNetwork> FromStr for MoneroPublicKey<N> {
    type Err = PublicKeyError;

    /// Returns a Monero public key from a concatenated public spend key and public view key.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 64 {
            return Err(PublicKeyError::InvalidByteLength(bytes.len()))
        }

        let (spend_key, view_key) = bytes.split_at(32);
        let public_spend_key = hex::encode(spend_key);
        let public_view_key = hex::encode(view_key);

        Ok(Self::from(public_spend_key.as_str(), public_view_key.as_str())?)
    }
}

impl <N: MoneroNetwork> Display for MoneroPublicKey<N> {
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

    fn test_from_private_key<N: MoneroNetwork>(
        expected_public_key: &MoneroPublicKey<N>,
        private_key: &MoneroPrivateKey<N>
    ) {
        let public_key = MoneroPublicKey::from_private_key(private_key);
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address<N: MoneroNetwork>(
        expected_address: &MoneroAddress<N>,
        expected_format: &Format,
        expected_network: &Network,
        public_key: &MoneroPublicKey<N>
    ) {
        let address = public_key.to_address(expected_format, expected_network).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_str<N: MoneroNetwork>(
        expected_public_spend_key: &str,
        expected_public_view_key: &str,
        expected_address: &str,
        expected_format: &Format,
    ) {
        let public_key = MoneroPublicKey::from(expected_public_spend_key, expected_public_view_key).unwrap();
        let address = public_key.to_address(expected_format).unwrap();
        assert_eq!(expected_public_spend_key, hex::encode(public_key.spend_key));
        assert_eq!(expected_public_view_key, hex::encode(public_key.view_key));
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
    }

    fn test_to_str<N: MoneroNetwork>(
        expected_public_spend_key: &str,
        expected_public_view_key: &str,
        public_key: &MoneroPublicKey<N>
    ) {
        assert_eq!(format!("({}, {})", expected_public_spend_key, expected_public_view_key), public_key.to_string());
    }

    mod standard_mainnet {
        use super::*;

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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(seed, _, (public_spend_key, public_view_key), _)| {
                let public_key = MoneroPublicKey::from(public_spend_key, public_view_key).unwrap();
                let private_key = MoneroPrivateKey::from_seed(&seed).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, _, (public_spend_key, public_view_key), address)| {
                let address = MoneroAddress::from_str(address).unwrap();
                let public_key = MoneroPublicKey::from(public_spend_key, public_view_key).unwrap();
                test_to_address(&address, &Format::Standard, &Network::Mainnet, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, _, (public_spend_key, public_view_key), address)| {
                test_from_str(
                    public_spend_key,
                    public_view_key,
                    address,
                    &Format::Standard);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, _, (public_spend_key, public_view_key), _)| {
                let public_key = MoneroPublicKey::from(public_spend_key, public_view_key).unwrap();
                test_to_str(public_spend_key, public_view_key, &public_key);
            });
        }
    }
}
use crate::address::MoneroAddress;
use crate::format::MoneroFormat;
use crate::network::MoneroNetwork;
use crate::public_key::MoneroPublicKey;
use wagyu_model::{no_std::Vec, Address, AddressError, PrivateKey, PrivateKeyError, PublicKey};

use core::{fmt, fmt::Display, marker::PhantomData, str::FromStr};
use curve25519_dalek::scalar::Scalar;
use hex;
use rand::Rng;
use tiny_keccak::keccak256;

/// Represents a Monero private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MoneroPrivateKey<N: MoneroNetwork> {
    /// The private spending key
    spend_key: [u8; 32],
    /// The private viewing key
    view_key: [u8; 32],
    /// Format
    format: MoneroFormat,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: MoneroNetwork> PrivateKey for MoneroPrivateKey<N> {
    type Address = MoneroAddress<N>;
    type Format = MoneroFormat;
    type PublicKey = MoneroPublicKey<N>;

    /// Returns a randomly-generated Monero private key.
    fn new<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError> {
        let random: [u8; 32] = rng.gen();
        Self::from_seed(hex::encode(random).as_str(), &MoneroFormat::Standard)
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

impl<N: MoneroNetwork> MoneroPrivateKey<N> {
    /// Returns a private key given seed bytes.
    pub fn from_seed(seed: &str, format: &MoneroFormat) -> Result<Self, PrivateKeyError> {
        let seed = hex::decode(seed)?;
        if seed.len() != 32 {
            return Err(PrivateKeyError::InvalidByteLength(seed.len()));
        }

        let mut s = [0u8; 32];
        s.copy_from_slice(seed.as_slice());
        let spend_key = Scalar::from_bytes_mod_order(s).to_bytes();

        let format = match format {
            MoneroFormat::Subaddress(major, minor) if *major == 0 && *minor == 0 => MoneroFormat::Standard,
            _ => *format,
        };

        Ok(Self {
            spend_key,
            view_key: Scalar::from_bytes_mod_order(keccak256(&spend_key)).to_bytes(),
            format,
            _network: PhantomData,
        })
    }

    /// Returns a private key given a private spend key.
    pub fn from_private_spend_key(private_spend_key: &str, format: &MoneroFormat) -> Result<Self, PrivateKeyError> {
        let key = hex::decode(private_spend_key)?;
        if key.len() != 32 {
            return Err(PrivateKeyError::InvalidByteLength(key.len()));
        }

        let mut spend_key = [0u8; 32];
        spend_key.copy_from_slice(key.as_slice());

        let format = match format {
            MoneroFormat::Subaddress(major, minor) if *major == 0 && *minor == 0 => MoneroFormat::Standard,
            _ => *format,
        };

        Ok(Self {
            spend_key,
            view_key: Scalar::from_bytes_mod_order(keccak256(&spend_key)).to_bytes(),
            format,
            _network: PhantomData,
        })
    }

    /// Update the private key format and returns a subaddress private view key.
    pub fn to_subaddress_private_view_key(&self, major: u32, minor: u32) -> [u8; 32] {
        if major == 0 && minor == 0 {
            [0u8; 32]
        } else {
            let mut derivation: Vec<u8> = b"SubAddr\x00"[..].into();
            derivation.extend(&self.view_key);
            derivation.extend(&major.to_le_bytes());
            derivation.extend(&minor.to_le_bytes());

            Scalar::from_bytes_mod_order(keccak256(&derivation)).to_bytes()
        }
    }

    /// Returns the private spend key of the Monero private key.
    pub fn to_private_spend_key(&self) -> [u8; 32] {
        self.spend_key
    }

    /// Returns the private spend key of the Monero private key.
    pub fn to_private_view_key(&self) -> [u8; 32] {
        self.view_key
    }

    /// Returns the format of the Monero address.
    pub fn format(&self) -> MoneroFormat {
        self.format.clone()
    }
}

impl<N: MoneroNetwork> FromStr for MoneroPrivateKey<N> {
    type Err = PrivateKeyError;
    fn from_str(seed: &str) -> Result<Self, PrivateKeyError> {
        Self::from_seed(seed, &MoneroFormat::Standard)
    }
}

impl<N: MoneroNetwork> Display for MoneroPrivateKey<N> {
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
        private_key: &MoneroPrivateKey<N>,
    ) {
        let public_key = private_key.to_public_key();
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address<N: MoneroNetwork>(
        expected_address: &str,
        expected_format: &MoneroFormat,
        private_key: &MoneroPrivateKey<N>,
    ) {
        let address = private_key.to_address(expected_format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_seed<N: MoneroNetwork>(
        expected_private_spend_key: &str,
        expected_private_view_key: &str,
        expected_address: &str,
        expected_format: &MoneroFormat,
        seed: &str,
    ) {
        let private_key = MoneroPrivateKey::<N>::from_seed(seed, expected_format).unwrap();
        assert_eq!(expected_private_spend_key, hex::encode(private_key.spend_key));
        assert_eq!(expected_private_view_key, hex::encode(private_key.view_key));
        assert_eq!(
            expected_address,
            private_key.to_address(expected_format).unwrap().to_string()
        );
    }

    fn test_from_private_spend_key<N: MoneroNetwork>(
        expected_private_view_key: &str,
        expected_address: &str,
        expected_format: &MoneroFormat,
        private_spend_key: &str,
    ) {
        let private_key = MoneroPrivateKey::<N>::from_private_spend_key(private_spend_key, expected_format).unwrap();
        assert_eq!(private_spend_key, hex::encode(private_key.spend_key));
        assert_eq!(expected_private_view_key, hex::encode(private_key.view_key));
        assert_eq!(
            expected_address,
            private_key.to_address(expected_format).unwrap().to_string()
        );
    }

    fn test_to_str<N: MoneroNetwork>(
        expected_private_spend_key: &str,
        expected_private_view_key: &str,
        private_key: &MoneroPrivateKey<N>,
    ) {
        assert_eq!(
            format!("({}, {})", expected_private_spend_key, expected_private_view_key),
            private_key.to_string()
        );
    }

    mod standard_mainnet {
        use super::*;

        type N = Mainnet;
        const FORMAT: &MoneroFormat = &MoneroFormat::Standard;

        // (seed, (private_spend_key, private_view_key), (public_spend_key, public_view_key), address)
        const KEYPAIRS: [(&str, (&str, &str), (&str, &str), &str); 5] = [
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                (
                    "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                    "5177c436f032666c572df97ab591cc6ac2da96ab6818a2f38d72b430aebbdc0a",
                ),
                (
                    "b9c5610a07f4344b27625155614fb1341dd0392c68482f101b820bc1e2b908e5",
                    "0df7c88054ae3c5f75c364257d064f42d660e6ea1184bd2a3af0d7455cb4e9ee",
                ),
                "48fRSJiQSp3Da61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xTungkh5",
            ),
            (
                "a90aaafd9d8112848ca44b3230fbda22974b0ba1b0e74870bda8825d6ff60b06",
                (
                    "a90aaafd9d8112848ca44b3230fbda22974b0ba1b0e74870bda8825d6ff60b06",
                    "498a9d7cc43b05eee500a60901c1007990ad5c0e637d72d5f6f5dfd86f50ec09",
                ),
                (
                    "07ab31ccf46bda1d9dee0344b03cf689fb1f9302bd1f13fe52048e73b258f1e1",
                    "cec2f7e6079ff911e6a4cc00942f18fa8abb0d247b27c41a785035136ff7412d",
                ),
                "41uxs7goiMo5xKdNQosRUhQ5b7EyyY6SWjYE8D1BLuoWemcoD3wWkpY3zfNpcgPtNjiua5wPQoB395Rnvy159VnY67GHR9b",
            ),
            (
                "cff04d7e8db3f7910f6044a61e079a6e006b878f1e31596441951148be3f030c",
                (
                    "cff04d7e8db3f7910f6044a61e079a6e006b878f1e31596441951148be3f030c",
                    "539e8ee06b61cb4a6ee3875b18b10d8ce113c93d3b766af7d7ca24dc2b3f3c01",
                ),
                (
                    "70dddd449b5011e08876d307a76bf2d6bbd04b2cff4f7e3e5fde3d352065b5a3",
                    "087fd0571b27542ff94e3cd88dfacf1f5c6d5736feec0a8e36e038107eed0741",
                ),
                "45uBYxmi472eZFce75VAobcvBkZW1jGhbBS7RBWSSp9rUGdKm6gYc5R92QaGLesxNJ6FF167AWws7Qnf8aayDvkN8Q5CqEU",
            ),
            (
                "3de1ab3ee61116692a18e2cbd0f4be70e19200262b9426ef2ea3c990d0068700",
                (
                    "3de1ab3ee61116692a18e2cbd0f4be70e19200262b9426ef2ea3c990d0068700",
                    "394c84948bd577a8cb1dffa4cbccb51f65ac5439f8e256b0a0374b320bc99802",
                ),
                (
                    "72d2c60260247ef57c875c1fbd51352368731d38f32cb050fd2ab27b9cb54d54",
                    "891a9b16a83efa53f56bac0412fe2cdfdfbfe6d8fbaf879cbc8fb28ec3a28553",
                ),
                "45yUzNd6Kzdi4XWQCPhauA6vW7nXkwDNXEYhFwy7c2NGF96rFUscKE9F3WFW3i6ixTeSrnpfMxgdCTDYP4sCcBkxANMA62p",
            ),
            (
                "7dc2f3340b8f41b6f5166235011d1fa58e7f2d32d761a56dc3e618255692c704",
                (
                    "7dc2f3340b8f41b6f5166235011d1fa58e7f2d32d761a56dc3e618255692c704",
                    "5a224a898a42d48025efccfb14c2062610ec95ddfe02c764e6ababe1ed44780d",
                ),
                (
                    "ccfc5403e256475e5824310864cff02da9badeeeae09c7a78baf920f89332b20",
                    "c1b9ecd218547d81c3a15a0c0c6b02f0a56def8748f39eef054397a9df27f5c9",
                ),
                "49PevuALZP4GnFxcmJLwt38dzKtg35WSiV2QMYfcQ6KU6UnKmkcUngCNhskr4Pu4ZwhFa3NY1jyRXgyoLPWBK4gcPmyURJg",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS
                .iter()
                .for_each(|(seed, _, (public_spend_key, public_view_key), _)| {
                    let public_key = MoneroPublicKey::<N>::from(public_spend_key, public_view_key, FORMAT).unwrap();
                    let private_key = MoneroPrivateKey::<N>::from_seed(seed, FORMAT).unwrap();
                    test_to_public_key(&public_key, &private_key);
                });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(seed, _, _, expected_address)| {
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, FORMAT).unwrap();
                test_to_address(expected_address, &MoneroFormat::Standard, &private_key);
            });
        }

        #[test]
        fn from_seed() {
            KEYPAIRS
                .iter()
                .for_each(|(seed, (private_spend_key, private_view_key), _, address)| {
                    test_from_seed::<N>(
                        private_spend_key,
                        private_view_key,
                        address,
                        &MoneroFormat::Standard,
                        seed,
                    );
                });
        }

        #[test]
        fn from_private_spend_key() {
            KEYPAIRS
                .iter()
                .for_each(|(_, (private_spend_key, private_view_key), _, address)| {
                    test_from_private_spend_key::<N>(
                        private_view_key,
                        address,
                        &MoneroFormat::Standard,
                        private_spend_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS
                .iter()
                .for_each(|(seed, (private_spend_key, private_view_key), _, _)| {
                    let private_key = MoneroPrivateKey::<N>::from_seed(seed, FORMAT).unwrap();
                    test_to_str(private_spend_key, private_view_key, &private_key);
                });
        }
    }

    mod integrated_mainnet {
        use super::*;

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
            KEYPAIRS
                .iter()
                .for_each(|(seed, _, (public_spend_key, public_view_key), payment_id, _)| {
                    let mut payment_id_bytes = [0u8; 8];
                    payment_id_bytes.copy_from_slice(&hex::decode(payment_id).unwrap());
                    let format = &MoneroFormat::Integrated(payment_id_bytes);
                    let public_key = MoneroPublicKey::<N>::from(public_spend_key, public_view_key, format).unwrap();
                    let private_key = MoneroPrivateKey::<N>::from_seed(seed, &format).unwrap();
                    test_to_public_key(&public_key, &private_key);
                });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(seed, _, _, payment_id, expected_address)| {
                let mut payment_id_bytes = [0u8; 8];
                payment_id_bytes.copy_from_slice(&hex::decode(payment_id).unwrap());
                let format = &MoneroFormat::Integrated(payment_id_bytes);
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, format).unwrap();
                test_to_address(expected_address, format, &private_key);
            });
        }

        #[test]
        fn from_seed() {
            KEYPAIRS.iter().for_each(
                |(seed, (private_spend_key, private_view_key), _, payment_id, address)| {
                    let mut payment_id_bytes = [0u8; 8];
                    payment_id_bytes.copy_from_slice(&hex::decode(payment_id).unwrap());
                    let format = &MoneroFormat::Integrated(payment_id_bytes);
                    test_from_seed::<N>(private_spend_key, private_view_key, address, format, seed);
                },
            );
        }

        #[test]
        fn from_private_spend_key() {
            KEYPAIRS
                .iter()
                .for_each(|(_, (private_spend_key, private_view_key), _, payment_id, address)| {
                    let mut payment_id_bytes = [0u8; 8];
                    payment_id_bytes.copy_from_slice(&hex::decode(payment_id).unwrap());
                    let format = &MoneroFormat::Integrated(payment_id_bytes);
                    test_from_private_spend_key::<N>(private_view_key, address, format, private_spend_key);
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS
                .iter()
                .for_each(|(seed, (private_spend_key, private_view_key), _, payment_id, _)| {
                    let mut payment_id_bytes = [0u8; 8];
                    payment_id_bytes.copy_from_slice(&hex::decode(payment_id).unwrap());
                    let format = &MoneroFormat::Integrated(payment_id_bytes);
                    let private_key = MoneroPrivateKey::<N>::from_seed(seed, format).unwrap();
                    test_to_str(private_spend_key, private_view_key, &private_key);
                });
        }
    }

    mod subaddress_mainnet {
        use super::*;

        type N = Mainnet;

        // (seed, (private_spend_key, private_view_key), (public_spend_key, public_view_key), major index, minor index, address)
        const KEYPAIRS: [(&str, (&str, &str), (&str, &str), u32, u32, &str); 8] = [
            (
                "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                (
                    "3eb8e283b45559d4d2fb6b3a4f52443b420e6da2b38832ea0eb642100c92d600",
                    "5177c436f032666c572df97ab591cc6ac2da96ab6818a2f38d72b430aebbdc0a",
                ),
                (
                    "b9c5610a07f4344b27625155614fb1341dd0392c68482f101b820bc1e2b908e5",
                    "0df7c88054ae3c5f75c364257d064f42d660e6ea1184bd2a3af0d7455cb4e9ee",
                ),
                0,
                0,
                "48fRSJiQSp3Da61k8NSR5J9ibWMBkrJHL3hGDxSaZJvsfK7jpigPWyyGy5jqs8MSgeCBQb1HR4NDS84goPRaLV2xTungkh5",
            ),
            (
                "cea3828e35d87623fe90bbb6f1adce4dcb120a1a84ed04c0977506f0497a1b01",
                (
                    "cea3828e35d87623fe90bbb6f1adce4dcb120a1a84ed04c0977506f0497a1b01",
                    "8f34cccca3f036147ae897af3fb1612a1f8a413fa81326efef00020528c71302",
                ),
                (
                    "9da052a0d0df379d39152bc6a89a87c6dd6bec7b66e33047c6f92391eb39b002",
                    "612cda80182066c2af6f6420e2f1e30916bf61d88a25a10255250ebf44d99299",
                ),
                0,
                0,
                "47bZXfYymK4TJG57p1XuRxaGErhGCvV7DD1L6CM9pNEs1Q5vyWcKDqwZZh6G9Jmmsp2XB3zyNzpek1PdVKuM5hEZJJLLfZG",
            ),
            (
                "001706196e622bdcb6ce34669206d28305be4700bdee6c07333488c05cbafd06",
                (
                    "001706196e622bdcb6ce34669206d28305be4700bdee6c07333488c05cbafd06",
                    "27482f2fa26968fa61bbedbb3a3675a51daf1d79b18b2e9c5cdf6d0382d7cb00",
                ),
                (
                    "4634bca440d1df8e7c2a590de506aedf082e679331ccf269ed5e794fdc7d1393",
                    "15ecbb48a0090ab64d15292322acfec104cf4a2d7081a89bc31a0eb1c63ea3e5",
                ),
                0,
                0,
                "44HR9cmBTqgQqHReeoeHLReJgz4FC8xVPJidMPeqao4eRbv52HyCnrdXVYr56otoqoZHXPqHKEVaPT465qS9Zm6rSv4uSoN",
            ),
            (
                "ebb4c2fd6815fa634e76a2f7dee6b96d6f4e64ede83e35c0a1963b0ae369550c",
                (
                    "ebb4c2fd6815fa634e76a2f7dee6b96d6f4e64ede83e35c0a1963b0ae369550c",
                    "f5e6520b8f7acd6c4730b15e3f636db5a221792a2877b645b476509de96e3c07",
                ),
                (
                    "23ef6136394ceed5dfe042bffe2f405b0e0effe890810d8a27023af40f0f49d7",
                    "5055a32401b6e2de7ab8948366d0da88f60ae2ea4d5bccdc847efdf1d881ee6d",
                ),
                0,
                1,
                "83pEcCq6G9TcmrLoC7MrcFGEM7TsEsNpLQ7FZmkq6pPAd1pC5ajkHUDeDL4dV724JDPuhGXJyajf1dtJCjJ6MTYqDP2bECQ",
            ),
            (
                "8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903",
                (
                    "8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903",
                    "99c57d1f0f997bc8ca98559a0ccc3fada3899756e63d1516dba58b7e468cfc05",
                ),
                (
                    "fe358188b528335ad1cfdc24a22a23988d742c882b6f19a602892eaab3c1b62b",
                    "9bc2b464de90d058468522098d5610c5019c45fd1711a9517db1eea7794f5470",
                ),
                0,
                1,
                "8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB",
            ),
            (
                "71d7544ca57116d3cc460e65bffbb124ae876a3e2d75e65e6e205053b951520b",
                (
                    "71d7544ca57116d3cc460e65bffbb124ae876a3e2d75e65e6e205053b951520b",
                    "cdf9ef49fbd4a7671e1d38b11d0f86d670cc4dc6b451d9bb17c08720a458dc09",
                ),
                (
                    "c3e41550f16d40cce1730f11d4d3d7a1be750a7a1a2908cc6ac9674d9908d3bd",
                    "19a39346ff0e86246ae0f3ef05e53bf810f8b194a216c3061192a510d609a39d",
                ),
                18,
                225,
                "89sosC3dvS3bGbkFfapXx2U47upjsn9SPbC6w4voYzhgYdWV6kotq4Z76J8TUUCw2aiVZ7yxsBySi21sfH5Zyh8nJkYpwHf",
            ),
            (
                "6e3c82cf5a2fe62b26eb6b09f1ffc8dc71a0e88f634aed371957428d546cd908",
                (
                    "6e3c82cf5a2fe62b26eb6b09f1ffc8dc71a0e88f634aed371957428d546cd908",
                    "f6bc23369a98f384f7312bcaeb509528981e3612ad93632796aaa191e426740c",
                ),
                (
                    "0686f15b60e426e31b7e1f2a6f78dc04b37b1588e21f928ea9b603f91a0937bc",
                    "b5d7f63cc989dfe971e7c9ef5df96810ace0ea72a16e9e08e02702e011f3baa4",
                ),
                5,
                7,
                "82hbfaudQXXezE7wRfRQJf1ncBMySUg2MQs1XpjyetpWYZj98mRo5sCg3i5y2XtJRV3nmjshgfaPX2V74B9cHFEZKYgezJB",
            ),
            (
                "ed8b4cae6db5548a129280750583bda7774d4ed9d4d44ecd7bc6cd7b17ace908",
                (
                    "ed8b4cae6db5548a129280750583bda7774d4ed9d4d44ecd7bc6cd7b17ace908",
                    "891a3487480a7854c5a9bff8fcf5652e4a1f9b71632dca4a81a49c251e858100",
                ),
                (
                    "a8c7fbd17a61ddb95d31075c2cf6d64902afcc4fb2656fcd66aaaf0b51d39307",
                    "f6ef2e3d049370d57ebd7ff023f05a799ac6193ff03394a5296a34dca8d0dcfc",
                ),
                20000,
                35000,
                "88rDu7NuEyiY1GGgLnFbXbDDJ1X85oa38bMeYrzmMMRL2LGTQqr7DgjciAqsntKTzhMLiaLFbKkMHUdH1tN7FBcPVYWuNYw",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS
                .iter()
                .for_each(|(seed, _, (public_spend_key, public_view_key), major, minor, _)| {
                    let format = &MoneroFormat::Subaddress(*major, *minor);
                    let private_key = MoneroPrivateKey::<N>::from_seed(seed, format).unwrap();
                    private_key.to_subaddress_private_view_key(*major, *minor);
                    let public_key = MoneroPublicKey::<N>::from(public_spend_key, public_view_key, format).unwrap();
                    test_to_public_key(&public_key, &private_key);
                });
        }

        #[test]
        fn to_address() {
            KEYPAIRS
                .iter()
                .for_each(|(seed, _, _, major, minor, expected_address)| {
                    let format = &MoneroFormat::Subaddress(*major, *minor);
                    let private_key = MoneroPrivateKey::<N>::from_seed(seed, format).unwrap();
                    private_key.to_subaddress_private_view_key(*major, *minor);
                    test_to_address(expected_address, format, &private_key);
                });
        }

        #[test]
        fn from_seed() {
            KEYPAIRS.iter().for_each(
                |(seed, (private_spend_key, private_view_key), _, major, minor, address)| {
                    test_from_seed::<N>(
                        private_spend_key,
                        private_view_key,
                        address,
                        &MoneroFormat::Subaddress(*major, *minor),
                        seed,
                    );
                },
            );
        }

        #[test]
        fn from_private_spend_key() {
            KEYPAIRS
                .iter()
                .for_each(|(_, (private_spend_key, private_view_key), _, major, minor, address)| {
                    test_from_private_spend_key::<N>(
                        private_view_key,
                        address,
                        &MoneroFormat::Subaddress(*major, *minor),
                        private_spend_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS
                .iter()
                .for_each(|(seed, (private_spend_key, private_view_key), _, major, minor, _)| {
                    let private_key =
                        MoneroPrivateKey::<N>::from_seed(seed, &MoneroFormat::Subaddress(*major, *minor)).unwrap();
                    test_to_str(private_spend_key, private_view_key, &private_key);
                });
        }
    }

    mod invalid_private_key {
        use super::*;
        type N = Mainnet;
        const FORMAT: &MoneroFormat = &MoneroFormat::Standard;

        const INVALID: [&str; 6] = [
            "",
            "a98213556a",
            "a98213556a454af1782d1fb80c95e34",
            "a98213556a454af1782d1fb80c95e3401897819b385e7a677",
            "a98213556a454af1782d1fb80c95e3401897819b385e7a6779ced7ecc4c00a0900",
            "a98213556a454af1782d1fb80c95e3401897819b385e7a6779ced7ecc4c00a09a98213556a454af1782d1fb80c95e3401897819b385e7a6779ced7ecc4c00a09"
        ];

        #[test]
        fn test_invalid_seed() {
            INVALID.iter().for_each(|seed| {
                let private_key = MoneroPrivateKey::<N>::from_seed(seed, FORMAT);
                assert!(private_key.is_err());
            });
        }

        #[test]
        fn test_invalid_private_spend_key() {
            INVALID.iter().for_each(|private_spend_key| {
                let private_key = MoneroPrivateKey::<N>::from_private_spend_key(private_spend_key, FORMAT);
                assert!(private_key.is_err());
            });
        }
    }
}

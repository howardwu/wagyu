use crate::network::ZcashNetwork;
use crate::private_key::ZcashPrivateKey;
use crate::public_key::{P2PKHViewingKey, SaplingViewingKey, SproutViewingKey, ViewingKey, ZcashPublicKey};
use wagyu_model::{
    crypto::{checksum, hash160},
    Address, AddressError, PrivateKey,
};

use base58::{FromBase58, ToBase58};
use bech32::{Bech32, FromBase32, ToBase32};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use sapling_crypto::primitives::Diversifier;
use serde::Serialize;
use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::{str, str::FromStr};
use zcash_primitives::JUBJUB;

/// Represents the format of a Zcash address
#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// Pay-to-Pubkey Hash, transparent address beginning with "t1" or "tm"
    P2PKH,
    /// Pay-to-Script Hash, transparent address beginning with "t3" or "t2"
    P2SH,
    /// Sprout shielded address beginning with "zc" or "zt"
    Sprout,
    /// Sapling shielded address beginning with "zs" or "ztestsapling"
    Sapling(Option<[u8; 11]>),
}

impl Format {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix<N: ZcashNetwork>(&self) -> Vec<u8> {
        N::to_address_prefix(self)
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, AddressError> {
        if prefix.len() < 2 {
            return Err(AddressError::InvalidPrefixLength(prefix.len()));
        }

        match prefix[1] {
            0xB8 | 0x25 => Ok(Format::P2PKH),
            0xBD | 0xBA => Ok(Format::P2SH),
            0x9A | 0xB6 => Ok(Format::Sprout),
            0x73 | 0x74 => Ok(Format::Sapling(None)),
            _ => return Err(AddressError::InvalidPrefix(prefix.clone())),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Format::P2PKH => write!(f, "p2pkh"),
            Format::P2SH => write!(f, "p2sh"),
            Format::Sprout => write!(f, "sprout"),
            Format::Sapling(_) => write!(f, "sapling"),
        }
    }
}

/// Represents a Zcash address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashAddress<N: ZcashNetwork> {
    /// The Zcash address
    address: String,
    /// The format of the address
    format: Format,
    /// The network on which this address is usable
    _network: PhantomData<N>,
}

impl<N: ZcashNetwork> Address for ZcashAddress<N> {
    type Format = Format;
    type PrivateKey = ZcashPrivateKey<N>;
    type PublicKey = ZcashPublicKey<N>;

    /// Returns the address corresponding to the given Zcash private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Result<Self, AddressError> {
        match private_key.to_public_key().to_viewing_key() {
            ViewingKey::P2PKH(public_key) => Ok(Self::p2pkh(&public_key)),
            ViewingKey::P2SH(_) => Ok(Self::p2sh()),
            ViewingKey::Sprout(public_key) => Self::sprout(&public_key),
            ViewingKey::Sapling(public_key) => Self::sapling(&public_key, format),
        }
    }

    /// Returns the address corresponding to the given Zcash public key.
    fn from_public_key(public_key: &Self::PublicKey, format: &Self::Format) -> Result<Self, AddressError> {
        match &public_key.to_viewing_key() {
            ViewingKey::P2PKH(public_key) => Ok(Self::p2pkh(&public_key)),
            ViewingKey::P2SH(_) => Ok(Self::p2sh()),
            ViewingKey::Sprout(public_key) => Self::sprout(&public_key),
            ViewingKey::Sapling(public_key) => Self::sapling(&public_key, format),
        }
    }
}

impl<N: ZcashNetwork> ZcashAddress<N> {
    /// Returns a transparent address from a given Zcash public key.
    pub fn p2pkh(public_key: &P2PKHViewingKey) -> Self {
        let mut address = [0u8; 26];
        address[0..2].copy_from_slice(&N::to_address_prefix(&Format::P2PKH));
        address[2..22].copy_from_slice(&hash160(&match public_key.compressed {
            true => public_key.public_key.serialize().to_vec(),
            false => public_key.public_key.serialize_uncompressed().to_vec(),
        }));

        let sum = &checksum(&address[0..22])[0..4];
        address[22..26].copy_from_slice(sum);

        Self {
            address: address.to_base58(),
            format: Format::P2PKH,
            _network: PhantomData,
        }
    }

    /// Returns a P2SH address.
    pub fn p2sh() -> Self {
        unimplemented!("p2sh addresses are unimplemented");
    }

    /// Returns a shielded address from a given Zcash public key.
    pub fn sprout(public_key: &SproutViewingKey) -> Result<Self, AddressError> {
        let pk = &Scalar::from_bits(public_key.key_b) * &ED25519_BASEPOINT_TABLE;

        let mut address = [0u8; 70];
        address[0..2].copy_from_slice(&N::to_address_prefix(&Format::Sprout));
        address[2..34].copy_from_slice(&public_key.key_a);
        address[34..66].copy_from_slice(pk.to_montgomery().as_bytes());

        let sum = &checksum(&address[0..66])[0..4];
        address[66..].copy_from_slice(sum);

        Ok(Self {
            address: address.to_base58(),
            format: Format::Sprout,
            _network: PhantomData,
        })
    }

    /// Returns a shielded address from a given Zcash public key.
    pub fn sapling(public_key: &SaplingViewingKey, format: &Format) -> Result<Self, AddressError> {
        // Randomness seeded by `getrandom`, which interfaces with the operating system
        // https://docs.rs/getrandom/
        let rng = &mut StdRng::from_entropy();

        let mut data: [u8; 11] = match format {
            Format::Sapling(data) => data.unwrap_or(rng.gen()),
            _ => rng.gen(),
        };

        let address;
        let diversifier;
        loop {
            if let Some(output) = public_key.0.vk.into_payment_address(Diversifier(data), &JUBJUB) {
                address = output;
                diversifier = data;
                break;
            }
            data = rng.gen();
        }

        let mut checked_data = vec![0; 43];
        checked_data[..11].copy_from_slice(&diversifier);
        address.pk_d.write(checked_data[11..].as_mut())?;

        let format = Format::Sapling(Some(diversifier));
        let prefix = N::to_address_prefix(&format);

        Ok(Self {
            address: Bech32::new(String::from(str::from_utf8(&prefix)?), checked_data.to_base32())?.to_string(),
            format: Format::Sapling(Some(diversifier)),
            _network: PhantomData,
        })
    }

    /// Returns the diversifier of a Zcash Sapling address.
    pub fn to_diversifier(&self) -> Option<String> {
        if let Format::Sapling(_) = self.format {
            Self::get_diversifier(&self.address).map(|d| hex::encode(d)).ok()
        } else {
            None
        }
    }

    /// Returns the diversifier of a specified Zcash Sapling address.
    pub fn get_diversifier(address: &str) -> Result<[u8; 11], AddressError> {
        let address = Bech32::from_str(address)?;
        let buffer: Vec<u8> = FromBase32::from_base32(address.data())?;
        let mut diversifier = [0u8; 11];
        diversifier.copy_from_slice(&buffer[0..11]);
        Ok(diversifier)
    }

    /// Returns the format of the Monero address.
    pub fn format(&self) -> Format {
        self.format.clone()
    }
}

impl<'a, N: ZcashNetwork> TryFrom<&'a str> for ZcashAddress<N> {
    type Error = AddressError;

    fn try_from(address: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(address)
    }
}

impl<N: ZcashNetwork> FromStr for ZcashAddress<N> {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() < 2 {
            return Err(AddressError::InvalidCharacterLength(address.len()));
        }

        // Transparent
        if &address[0..=0] == "t" && address.len() < 40 {
            match &address[1..=1] {
                "1" | "m" => {
                    let data = address.from_base58()?;
                    if data.len() != 26 {
                        return Err(AddressError::InvalidByteLength(data.len()));
                    }

                    // Check that the network bytes correspond with the correct network.
                    let _ = N::from_address_prefix(&data[0..2].to_vec())?;
                    let format = Format::from_address_prefix(&data[0..2].to_vec())?;

                    return Ok(Self {
                        address: address.into(),
                        format,
                        _network: PhantomData,
                    });
                }
                "3" | "2" => {
                    unimplemented!("");
                }
                _ => return Err(AddressError::InvalidAddress(address.into())),
            }
        }

        // Shielded
        if &address[0..=0] == "z" && address.len() > 77 {
            if &address[0..12] == "ztestsapling" && address.len() > 87 {
                // Check that the network bytes correspond with the correct network.
                let _ = N::from_address_prefix(&address[0..12].as_bytes().to_vec())?;
                let format = Format::Sapling(Some(Self::get_diversifier(address)?));

                return Ok(Self {
                    address: address.into(),
                    format,
                    _network: PhantomData,
                });
            } else if &address[0..2] == "zs" && address.len() > 77 {
                // Check that the network bytes correspond with the correct network.
                let _ = N::from_address_prefix(&address[0..2].as_bytes().to_vec())?;
                let format = Format::Sapling(Some(Self::get_diversifier(address)?));

                return Ok(Self {
                    address: address.into(),
                    format,
                    _network: PhantomData,
                });
            } else if &address[0..2] == "zt" && address.len() == 95 {
                let data = address.from_base58()?;

                // Check that the network bytes correspond with the correct network.
                let _ = N::from_address_prefix(&data[0..2].to_vec())?;
                let format = Format::Sprout;

                return Ok(Self {
                    address: address.into(),
                    format,
                    _network: PhantomData,
                });
            } else if &address[0..2] == "zc" && address.len() == 95 {
                let data = address.from_base58()?;

                // Check that the network bytes correspond with the correct network.
                let _ = N::from_address_prefix(&data[0..2].to_vec())?;
                let format = Format::Sprout;

                return Ok(Self {
                    address: address.into(),
                    format,
                    _network: PhantomData,
                });
            }
        }

        Err(AddressError::InvalidAddress(address.into()))
    }
}

impl<N: ZcashNetwork> fmt::Display for ZcashAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;
    use wagyu_model::public_key::PublicKey;

    fn test_from_private_key<N: ZcashNetwork>(
        expected_address: &str,
        private_key: &ZcashPrivateKey<N>,
        format: &Format,
    ) {
        let address = ZcashAddress::<N>::from_private_key(private_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key<N: ZcashNetwork>(expected_address: &str, public_key: &ZcashPublicKey<N>, format: &Format) {
        let address = ZcashAddress::<N>::from_public_key(public_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str<N: ZcashNetwork>(expected_address: &str, expected_format: &Format) {
        let address = ZcashAddress::<N>::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
    }

    fn test_to_str<N: ZcashNetwork>(expected_address: &str, address: &ZcashAddress<N>) {
        assert_eq!(expected_address, address.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "KxYzZuBPkE3rnEEGCdsB6dCzxN1D4xoY5ogKoxbdUdkxbRzvgbij",
                "t1MoMR1XdnPqLBWf5XkchWTkGNrveYLCaiM",
            ),
            (
                "KyuC6qNxMiuPEF4wp6eLsJuczLKqHsdsdSx5c3a1boY81mpahuR6",
                "t1cnUnLfXZsb7gM7h9zD6QXm1wEDi4NxvTi",
            ),
            (
                "KxNLHESzCRfzTfF9KGsF68QtV9fT9qFRAH5UKpVUdMvc4TTcBmhJ",
                "t1VenYPx8HCiq6YFbuh1HbLGwtDZxQ5hQCr",
            ),
            (
                "L5XgV3xUnqcqJyJm3JZmtZyj5i8FmUbuj9LCz9n3FA87Ertn2Qod",
                "t1U9A7fh864FCzePbrXeUdjvuMfuCYKijbr",
            ),
            (
                "L17dC6ZcGfKu84FGastka34sB8yV9fzgbKJaafVWi4zKs6ETnF2x",
                "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = ZcashPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &Format::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "5HwduFgmNrhcgXpD7TH2ZbqBzfET3FzRLwapJdZYUNyxPz6MYQU",
                "t1gxf6ykX23Ha3Bf1bKhjJzdxtCPratotJK",
            ),
            (
                "5KFcAbDaap4ZqF1pCTq6rKWU6bUZg3bnqHJYaCEh6NUu8aVTszm",
                "t1QnYYpiVpmwHPtrRSJqypnDxG77284NUtj",
            ),
            (
                "5KXotG2j5THVbdf2Uf87HPZFRNaVqZYrrBVnZzczyDVza39q94f",
                "t1XEXEt3KeEYzycPTzn3invLivktYifWuXJ",
            ),
            (
                "5KPN7LeX6uzBpTYdC28xjgHkN5XbCKZVJiu9QquSCEFJcD7ndnv",
                "t1VxdN6a4T6RiSwgkNURkHhjLuoThvZWaHC",
            ),
            (
                "5JewwWXmgcdk9P762F3Pdr8RBcWfWVAAotq9mjSNBcEvZsQBJ32",
                "t1XraTEGoX5QjnhAqDs9F8AqvDEh4zohhUQ",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = ZcashPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &Format::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cPFtCjL9EXtgZQJSD13NMn1p3mhoXXHSqF9kXEX97XNPsz1b97ti",
                "tmW3honY9Uz7WhSJPwRD5UPHY942RpoYcPM",
            ),
            (
                "cRbB17stVTkcZ38o8xx6qRQod6Ucof55YgLa86yL8jtwVr1YfgcB",
                "tmP5MuXAzJEPS3GvjBeAiZUmrzYxuC6dUHv",
            ),
            (
                "cMm7vvjXYJGqLCTc1FcQmmteXYGNduUAVS25WCvyqQvWNTENabQF",
                "tmPeoJrhUAhcb4nXS3mCqdSBJuGTcX6s2sm",
            ),
            (
                "cVrMaRzQ4YkbQSJr595Lr9aem2UHomoFikSQNPKqHoZUdaicJBa6",
                "tmNEZVphFWo5vh5xfb1k5STFFMZ6yijzfKC",
            ),
            (
                "cNLN6kBQJ68w1idp9TiUDbiLPnZ9vm9THDXE6nGBER1g7Pv4GycX",
                "tmL1yemb1GvbS4SUzYQTirdGm7WSDREQgow",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = ZcashPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &Format::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "91fek9Xs6SkDx9mm89hDNM84Y49yM446xKmdQDsLJ4uzUXX2jLg",
                "tmYkTUt1hBUcHyKtGpXYRM3tVrnL32fWDhi",
            ),
            (
                "934pAaCKAS9vb1GmiSc3tfmVbrvREF1VBo19YdEXGWEwZUee4pP",
                "tmHe2je7jqn9a7k4wpjidTCZTmFcKKUPgFu",
            ),
            (
                "91eKu9FmVPqPZTLMBwyGZygwtsFzxj49p3tF7DWGkLETUsWP7gv",
                "tmQWZNqKkn2JUJUa4DKZpzFZyN3tTLqZtMy",
            ),
            (
                "923PCzFXfoZ9sXrkBb4e1m8UzvWXATPY4uaxvLPGofCPM4AtS11",
                "tmJsXk5QzyvXCkNApr5PG6DXeHUfHbQWJsV",
            ),
            (
                "93UmH7crxTbPxq8mdJ9Vmzvk1nGEwVh4LDbg9iF7pJ2sezShhRX",
                "tmDM9R3iW5AGzmUWAPnMxCVkZYR7LLKbcnX",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = ZcashPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &Format::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod sprout_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "SKxt8pwrQipUL5KgZUcBAqyLj9R1YwMuRRR3ijGMCwCCqchmi8ut",
                "zcJLC7a3aRJohMNCVjSZQ8jFuofhAHJNAY4aX5soDkYfgNejzKnEZbucJmVibLWCwK8dyyfDhNhf3foXDDTouweC382LcX5",
            ),
            (
                "SKxoo5QkFQgTbdc6EWRKyHPMdmtNDJhqudrAVhen9b4kjCwN6CeV",
                "zcRYvLiURno1LhXq95e8avXFcH2fKKToSFfhqaVKTy8mGH7i6SJbfuWcm4h9rEA6DvswrbxDhFGDQgpdDYV8zwUoHvwNvFX",
            ),
            (
                "SKxsVGKsCESoVb3Gfm762psjRtGHmjmv7HVjHckud5MnESfktUuG",
                "zcWGguu2UPfNhh1ygWW9Joo3osvncsuehtz5ewvXd78vFDdnDCRNG6QeKSZpwZmYmkfEutPVf8HzCfBytqXWsEcF2iBAM1e",
            ),
            (
                "SKxp72QGQ2qtovHSoVnPp8jRFQpHBhG1xF8s27iRFjPXXkYMQUA6",
                "zcWZomPYMEjJ49S4UHcvTnhjYqogfdYJuEDMURDpbkrz94bkzdTdJEZKWkkpQ8nK62eyLkZCvLZDFtLC2Cq5BmEK3WCKGMN",
            ),
            (
                "SKxpmLdykLu3xxSXtw1EA7iLJnXu8hFh8hhmW1B2J2194ijh5CR4",
                "zcgjj3fJF59QGBufopx3F51jCjUpXbgEzec7YQT6jRt4Ebu5EV3AW4jHPN6ZdXhmygBvQDRJrXoZLa3Lkh5GqnsFUzt7Qok",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &Format::Sprout);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::Sprout);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &Format::Sprout);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod sapling_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "secret-spending-key-main1hd5umd08pc4m6f8hw8x3tgv26kxn4w0p4g72kxrtndjazlm64hhsnczrtx",
                "zs1dq9dlh6u6hna0u96aqtynxt3acddtgkgdx4re65500nmc2aze0my65ky36vaqvj4hkc9ut66eyf",
            ),
            (
                "secret-spending-key-main100nf0tdkdumdx7cjmndaagu0htkgxszq9hjrhlspdu7ppd48yg8qxd0yqa",
                "zs1vvdj0st065ngdruymdcdy63duuavjeww3a2yyeu5tsqj2azhvwgkcaw9ngggfas6h4z4whnkpwz",
            ),
            (
                "secret-spending-key-main1pj046u8243rgvg2s4clj5nhvc6r48fe9vl4kvggdlrsc4y2ztt0skswpn9",
                "zs1akf8swew32rr4n63qedewhp2yz3wcjeazp6efs82lgealmux0h30ayju440rqyuscdr3wd5yuap",
            ),
            (
                "secret-spending-key-main1ls0d46g5d4w8lyucsudvpyyhl6nvzkf733ak7vuy4um0l8xrkthqnh9a7d",
                "zs14q3vapgrd6wfs9pr7hfy37y9djm3gnq09ztxsqs2x2vzv0lck978843q8r2ysejgwp9mcx7ws48",
            ),
            (
                "secret-spending-key-main1vqu0tez5nryjah27dgjc30xw0096cczwf6p9aecpt5glx0g7jees99g9fe",
                "zs1rzjhudlm99h5fyrh7dfsvkfg9l5z587w97pm3ce9hpwfxpgck6p55lwu5mcapz7g3r40y597n2c",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(
                    address,
                    &private_key,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(address).unwrap())),
                );
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = ZcashPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(
                    address,
                    &public_key,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(address).unwrap())),
                );
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(
                    address,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(address).unwrap())),
                );
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod sapling_testnet {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "secret-spending-key-test1fygsm6l3ltqqs63040tq426p85pgzuetdeg6q0wka38nx3rfa70sa9qp0v",
                "ztestsapling1jzzt7gjscav7lmdpemknv0v8rmmdzpcaqrx95azrgaky94drrvf0fg4wlnlkaclqj3r3s23g2sf",
            ),
            (
                "secret-spending-key-test1f6w469xhw65naz4pm4lxnmd8em7ev5ddzszy8js325lr0xe2ay9snuw9t5",
                "ztestsapling19epsvtxnzf59pr993fq4g0gu0fmrn2jl2z9jm2lgj3220c7r9shyvcpe25ul7wxvzk60z82zyf7",
            ),
            (
                "secret-spending-key-test1s4zwnn7xgglz9099kc4l2ejfl5m3ddkvpy3erm960raszl2lakss48u07t",
                "ztestsapling18ur694qcm6w657u9xt8aekutn98gyvpzwzjgjz99594x775ppeze5vwnp2ndw0u205vkuh2tqcu",
            ),
            (
                "secret-spending-key-test1d5seqlm269xjsgmz2qmwp9g683tx6n0hkyqalv5fjyraqt5mmz7snwyhek",
                "ztestsapling1hkyeldalqna6kxzkkpc3gl4yvtd842sld4kkx7mhtm4srhndnqm347q7x672t05j245skqsctvs",
            ),
            (
                "secret-spending-key-test1mqq09wgeevr0wwt2ncjncalktcwtt7tjxuk2cxtwce2xuzf4t0lqf5jn03",
                "ztestsapling12n4jm24lflgmjk4crm0322p0gpmww98v5cqyurphq6tr4r4q9kxyz2f3tp9x92mm8kruwwg2u5w",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(
                    address,
                    &private_key,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(address).unwrap())),
                );
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = ZcashPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(
                    address,
                    &public_key,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(address).unwrap())),
                );
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(
                    address,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(address).unwrap())),
                );
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    #[test]
    fn test_p2pkh_invalid() {
        type N = Mainnet;

        // Mismatched keypair

        let private_key = "KxYzZuBPkE3rnEEGCdsB6dCzxN1D4xoY5ogKoxbdUdkxbRzvgbij";
        let expected_address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt";

        let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
        let address = ZcashAddress::<N>::from_private_key(&private_key, &Format::P2PKH).unwrap();
        assert_ne!(expected_address, address.to_string());

        let public_key = ZcashPublicKey::<N>::from_private_key(&private_key);
        let address = ZcashAddress::<N>::from_public_key(&public_key, &Format::P2PKH).unwrap();
        assert_ne!(expected_address, address.to_string());

        // Invalid address length

        let address = "t";
        assert!(ZcashAddress::<N>::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3";
        assert!(ZcashAddress::<N>::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZ";
        assert!(ZcashAddress::<N>::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZtt1J8w8EMM1Rs26zJFu3";
        assert!(ZcashAddress::<N>::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZtt1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt";
        assert!(ZcashAddress::<N>::from_str(address).is_err());
    }
}

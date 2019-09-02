use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use crate::private_key::BitcoinPrivateKey;
use crate::public_key::BitcoinPublicKey;
use crate::witness_program::WitnessProgram;
use wagyu_model::{
    crypto::{checksum, hash160},
    Address, AddressError, PrivateKey,
};

use base58::{FromBase58, ToBase58};
use bech32::{u5, Bech32, FromBase32, ToBase32};
use std::{convert::TryFrom, fmt, marker::PhantomData, str::FromStr};

/// Represents a Bitcoin address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinAddress<N: BitcoinNetwork> {
    /// The Bitcoin address
    address: String,
    /// The format of the address
    format: BitcoinFormat,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: BitcoinNetwork> Address for BitcoinAddress<N> {
    type Format = BitcoinFormat;
    type PrivateKey = BitcoinPrivateKey<N>;
    type PublicKey = BitcoinPublicKey<N>;

    /// Returns the address corresponding to the given Bitcoin private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Result<Self, AddressError> {
        let public_key = private_key.to_public_key();
        match format {
            BitcoinFormat::P2PKH => Self::p2pkh(&public_key),
            BitcoinFormat::P2SH_P2WPKH => Self::p2sh_p2wpkh(&public_key),
            BitcoinFormat::Bech32 => Self::bech32(&public_key),
        }
    }

    /// Returns the address corresponding to the given Bitcoin public key.
    fn from_public_key(public_key: &Self::PublicKey, format: &Self::Format) -> Result<Self, AddressError> {
        match format {
            BitcoinFormat::P2PKH => Self::p2pkh(public_key),
            BitcoinFormat::P2SH_P2WPKH => Self::p2sh_p2wpkh(public_key),
            BitcoinFormat::Bech32 => Self::bech32(public_key),
        }
    }
}

impl<N: BitcoinNetwork> BitcoinAddress<N> {
    /// Returns a P2PKH address from a given Bitcoin public key.
    pub fn p2pkh(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let public_key = match public_key.is_compressed() {
            true => public_key.to_secp256k1_public_key().serialize().to_vec(),
            false => public_key.to_secp256k1_public_key().serialize_uncompressed().to_vec(),
        };

        let mut address = [0u8; 25];
        address[0] = N::to_address_prefix(&BitcoinFormat::P2PKH)[0];
        address[1..21].copy_from_slice(&hash160(&public_key));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Ok(Self {
            address: address.to_base58(),
            format: BitcoinFormat::P2PKH,
            _network: PhantomData,
        })
    }

    /// Returns a P2SH_P2WPKH address from a given Bitcoin public key.
    pub fn p2sh_p2wpkh(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let mut address = [0u8; 25];
        address[0] = N::to_address_prefix(&BitcoinFormat::P2SH_P2WPKH)[0];
        address[1..21].copy_from_slice(&hash160(&Self::create_redeem_script(public_key)));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Ok(Self {
            address: address.to_base58(),
            format: BitcoinFormat::P2SH_P2WPKH,
            _network: PhantomData,
        })
    }

    /// Returns a Bech32 address from a given Bitcoin public key.
    pub fn bech32(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let redeem_script = Self::create_redeem_script(public_key);
        let version = u5::try_from_u8(redeem_script[0])?;

        let mut data = vec![version];
        data.extend_from_slice(&redeem_script[2..].to_vec().to_base32());

        let bech32 = Bech32::new(String::from_utf8(N::to_address_prefix(&BitcoinFormat::Bech32))?, data)?;

        Ok(Self {
            address: bech32.to_string(),
            format: BitcoinFormat::Bech32,
            _network: PhantomData,
        })
    }

    /// Returns the format of the Bitcoin address.
    pub fn format(&self) -> BitcoinFormat {
        self.format.clone()
    }

    /// Returns a redeem script for a given Bitcoin public key.
    fn create_redeem_script(public_key: &<Self as Address>::PublicKey) -> [u8; 22] {
        let mut redeem = [0u8; 22];
        redeem[1] = 0x14;
        redeem[2..].copy_from_slice(&hash160(&public_key.to_secp256k1_public_key().serialize()));
        redeem
    }
}

impl<'a, N: BitcoinNetwork> TryFrom<&'a str> for BitcoinAddress<N> {
    type Error = AddressError;

    fn try_from(address: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(address)
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinAddress<N> {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() < 14 || address.len() > 74 {
            return Err(AddressError::InvalidCharacterLength(address.len()));
        }

        let prefix = &address.to_lowercase()[0..2];

        if let Ok(format) = BitcoinFormat::from_address_prefix(prefix.as_bytes()) {
            if BitcoinFormat::Bech32 == format {
                let bech32 = Bech32::from_str(&address)?;
                if bech32.data().is_empty() {
                    return Err(AddressError::InvalidAddress(address.to_owned()));
                }

                let data = bech32.data();
                let version = data[0].to_u8();
                let mut program = Vec::from_base32(&data[1..])?;

                let mut data = vec![version, program.len() as u8];
                data.append(&mut program);

                // Check that the witness program is valid.
                let _ = WitnessProgram::new(data.as_slice())?;
                // Check that the address prefix corresponds to the correct network.
                let _ = N::from_address_prefix(prefix.as_bytes())?;

                return Ok(Self {
                    address: address.to_owned(),
                    format: BitcoinFormat::Bech32,
                    _network: PhantomData,
                });
            }
        }

        let data = address.from_base58()?;
        if data.len() != 25 {
            return Err(AddressError::InvalidByteLength(data.len()));
        }

        // Check that the address prefix corresponds to the correct network.
        let _ = N::from_address_prefix(&data[0..2])?;
        let format = BitcoinFormat::from_address_prefix(&data[0..2])?;

        Ok(Self {
            address: address.into(),
            format,
            _network: PhantomData,
        })
    }
}

impl<N: BitcoinNetwork> fmt::Display for BitcoinAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;
    use wagyu_model::public_key::PublicKey;

    fn test_from_private_key<N: BitcoinNetwork>(
        expected_address: &str,
        private_key: &BitcoinPrivateKey<N>,
        format: &BitcoinFormat,
    ) {
        let address = BitcoinAddress::from_private_key(private_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key<N: BitcoinNetwork>(
        expected_address: &str,
        public_key: &BitcoinPublicKey<N>,
        format: &BitcoinFormat,
    ) {
        let address = BitcoinAddress::from_public_key(public_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str<N: BitcoinNetwork>(expected_address: &str, expected_format: &BitcoinFormat) {
        let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
    }

    fn test_to_str<N: BitcoinNetwork>(expected_address: &str, address: &BitcoinAddress<N>) {
        assert_eq!(expected_address, address.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "L2o7RUmise9WoxNzmnVZeK83Mmt5Nn1NBpeftbthG5nsLWCzSKVg",
                "1GUwicFwsZbdE3XyJYjmPryiiuTiK7mZgS",
            ),
            (
                "KzjKw25tuQoiDyQjUG38ZRNBdnfr5eMBnTsU4JahrVDwFCpRZP1J",
                "1J2shZV5b53GRVmTqmr3tJhkVbBML29C1z",
            ),
            (
                "L2N8YRtxNMAVFAtxBt9PFSADtdvbmzFFHLSU61CtLdhYhrCGPfWh",
                "13TdfCiGPagApSJZu1o1Y3mpfqpp6oK2GB",
            ),
            (
                "KwXH1Mu4FBtGN9nRn2VkBpienaVGZKvCAkZAdE96kK71dHR1oDRs",
                "1HaeDGHf3A2Uxeh3sKjVLYTn1hnEyuzLjF",
            ),
            (
                "KwN7qiBnU4GNhboBhuPaPaFingTDKU4r27pGggwQYz865TvBT74V",
                "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "5K9VY2kaJ264Pj4ygobGLk7JJMgZ2i6wQ9FFKEBxoFtKeAXPHYm",
                "18Bap2Lh5HJckiZcg8SYXoF5iPxkUoCN8u",
            ),
            (
                "5KiudZRwr9wH5auJaW66WK3CGR1UzL7ZXiicvZEEaFScbbEt9Qs",
                "192JSK8wNP867JGxHNHay3obNSXqEyyhtx",
            ),
            (
                "5KCxYELatMGyVZfZFcSAw1Hz4ngiURKS22x7ydNRxcXfUzhgWMH",
                "1NoZQSmjYHUZMbqLerwmT4xfe8A6mAo8TT",
            ),
            (
                "5KT9CMP2Kgh2Afi8GbmFAHJXsH5DhcpH9KY3aH4Hkv5W6dASy7F",
                "1NyGFd49x4nqoau8RJvjf9tGZkoUNjwd5a",
            ),
            (
                "5J4cXobHh2cF2MHpLvTFjEHZCtrNHzyDzKGE8LuST2VWP129pAE",
                "17nsg1F155BR6ie2miiLrSnMhF8GWcGq6V",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }

        #[test]
        fn test_invalid() {
            // Mismatched keypair

            let private_key = "5K9VY2kaJ264Pj4ygobGLk7JJMgZ2i6wQ9FFKEBxoFtKeAXPHYm";
            let expected_address = "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J";

            let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
            let address = BitcoinAddress::<N>::from_private_key(&private_key, &BitcoinFormat::P2PKH).unwrap();
            assert_ne!(expected_address, address.to_string());

            let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
            let address = BitcoinAddress::<N>::from_public_key(&public_key, &BitcoinFormat::P2PKH).unwrap();
            assert_ne!(expected_address, address.to_string());

            // Invalid address length

            let address = "1";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());

            let address = "12WMrNLRosydPNN";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());

            let address = "12WMrNLRosydPNNYM96dwk9jDv8rDRom3";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());

            let address = "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J12WMrNLRosydPNNYM";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());

            let address = "12WMrNLRosydPNNYM96dwk9jDv8rDRom3J12WMrNLRosydPNNYM96dwk9jDv8rDRom3J";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cSCkpm1oSHTUtX5CHdQ4FzTv9qxLQWKx2SXMg22hbGSTNVcsUcCX",
                "mwCDgjeRgGpfTMY1waYAJF2dGz4Q5XAx6w",
            ),
            (
                "cNp5uMWdh68Nk3pwShjxsSwhGPoCYgFvE1ANuPsk6qhcT4Jvp57n",
                "myH91eNrQKuuM7TeQYYddzL4URn6HiYbxW",
            ),
            (
                "cN9aUHNMMLT9yqBJ3S5qnEPtP11nhT7ivkFK1FqNYQMozZPgMTjJ",
                "mho8tsQtF7fx2bPKudMcXvGpUVYRHHiH4m",
            ),
            (
                "cSRpda6Bhog5SUyot96HSwSzn7FZNWzudKzoCzkgZrf9hUaL3Ass",
                "n3DgWHuAkg7eiPGH5gP8jeg3SbHBhuPJWS",
            ),
            (
                "cTqLNf3iCaW61ofgmyf4ZxChUL8DZoCEPmNTCKRsexLSdNuGWQT1",
                "mjhMXrTdq4X1dcqTaNDjwGdVaJEGBKpCRj",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "934pVYUzZ7Sm4ZSP7MtXaQXAcMhZHpFHFBvzfW3epFgk5cWeYih",
                "my55YLK4BmM8AyUW5px2HSSKL4yzUE5Pho",
            ),
            (
                "91dTfyLPPneZA6RsAXqNuT6qTQdAuuGVCUjmBtzgd1Tnd4RQT5K",
                "mw4afqNgGjn34okVmv9qH2WkvhfyTyNbde",
            ),
            (
                "92GweXA6j4RCF3zHXGGy2ShJq6T7u9rrjmuYd9ktLHgNrWznzUC",
                "moYi3FQZKtcc66edT3uMwVQCcswenpNscU",
            ),
            (
                "92QAQdzrEDkMExM9hHV5faWqKTdXcTgXguRBcyAyYqFCjVzhDLE",
                "mpRYQJ64ofurTCA3KKkaCjjUNqjYkUvB4w",
            ),
            (
                "92H9Kf4ikaqNAJLc5tbwvbmiBWJzNDGtYmnvrigZeDVD3aqJ85Q",
                "mvqRXtgQKqumMosPY3dLvhdYsQJV2AswkA",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2sh_p2wpkh_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "L3YPi4msjWdkqiH3ojfg3nwDmNYBrDScAtcugYBJSgsc3HTcqqjP",
                "38EMCierP738rgYVHjj1qJANHKgx1166TN",
            ),
            (
                "KxxFoGgBdqqyGznT6he2wKYcFKm5urSANec7qjLeu3caEadSo5pv",
                "3Kc9Vqzi4eUn42g1KWewVPvtTpWpUwjNFv",
            ),
            (
                "KziUnVFNBniwmvei7JvNJNcQZ27TDZe5VNn7ieRNK7QgMEVfKdo9",
                "3C2niRgmFP2kz47AAWASqq5nWobDke1AfJ",
            ),
            (
                "Kx5veRe18jnV1rZiJA7Xerh5qLpwnbjV38r83sKcF1W9d1K2TGSp",
                "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK",
            ),
            (
                "L4RrcBy6hZMw3xD4eAFXDTWPhasd9N3rYrYgfiR9pnGuLdv7UsWZ",
                "3LW5tQGWBCiRLfCgk1FEUpwKoymFF8Lk7P",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &BitcoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &BitcoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }

        #[test]
        fn test_invalid() {
            // Mismatched keypair

            let private_key = "L3YPi4msjWdkqiH3ojfg3nwDmNYBrDScAtcugYBJSgsc3HTcqqjP";
            let expected_address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK";

            let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
            let address = BitcoinAddress::<N>::from_private_key(&private_key, &BitcoinFormat::P2SH_P2WPKH).unwrap();
            assert_ne!(expected_address, address.to_string());

            let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
            let address = BitcoinAddress::<N>::from_public_key(&public_key, &BitcoinFormat::P2SH_P2WPKH).unwrap();
            assert_ne!(expected_address, address.to_string());

            // Invalid address length

            let address = "3";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());

            let address = "3Pai7Ly86pddxxwZ7";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());

            let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNY";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());

            let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK3Pai7Ly86pddxxwZ7";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());

            let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK";
            assert!(BitcoinAddress::<N>::from_str(address).is_err());
        }
    }

    mod p2sh_p2wpkh_testnet {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cSoLwgnCNXck57BGxdGRV4SQ42EUExV6ykdMK1RKwcEaB9MDZWki",
                "2N9e892o8DNZs25xHBwRPZLsrZK3dBsrH3d",
            ),
            (
                "cQEUStvLToCNEQ6QGPyTmGFCTiMWWzQDkkj2tUPEiAzafybgUyu4",
                "2MwX52EZPfK1sq12H3ikgTybrUvKG62b9rV",
            ),
            (
                "cRv6jkNhTNEL7563ezNuwWP9W7gEcjh19YbmHtTbrDUQsXF5PjoG",
                "2N2XaYpYxX6C6attRQ1NXJUgZdm861CPHJ7",
            ),
            (
                "cNyZJwad53Y38RthGrmYyoHAtsT7cPisjW92HJ4RcAP1mC6xBpSm",
                "2N3HzUQ4DzfEbxYp3XtpEKBBSdBS1uc2DLk",
            ),
            (
                "cUqEZZwzvdWv6pmnWV5eb68hNeWt3jDZgtCGf66rqk3bnbsXArVE",
                "2N5isk4qJHAKfLV987ePAqjLobJkrWVCuhj",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &BitcoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &BitcoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod bech32_mainnet {
        use super::*;
        use crate::public_key::BitcoinPublicKey;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "KyQ2StwnZ644hRLXdMrRUBGKT9WJcVVhnuzz2u528VHeAr5kFimR",
                "bc1qztqceddvavsxdgju4cz6z42tawu444m8uttmxg",
            ),
            (
                "L3aeYHnEBqNt6tKTgUyweY9HvZ3mcLMsq7KQZkSu9Mj8Z1JN9oC2",
                "bc1q0s92yg9m0zqjjc07z5lhhlu3k6ue93fgzku2wy",
            ),
            (
                "L3w7zoPzip7o6oXz3zVLNHbT2UyLBWuVG7uaEZDqneRjgjw9vmCE",
                "bc1q7rzq3xup0hdklkg6p8harn97zszuqwuaqc9l8t",
            ),
            (
                "L2C75eEmRTU8yWeSwtQ6xeumoNVmCb2uEMfzuo5dkdMwpUWwYtRU",
                "bc1qgw90ly6jkpprh6g8atk5cxnwcavh4e0p2k3h65",
            ),
            (
                "L2CJfT3w1VPDDLQfJKTmSb6gtSGyE1HxWYsitaq5Y1XLXTMC5Qmx",
                "bc1qgfzgf6pzuk7y88zk54nxluzg6dv9jett9suzuf",
            ),
        ];

        const INVALID: [&str; 7] = [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // invalid checksum
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", // invalid witness version
            "bc1rw5uspcuh",                               // invalid program length
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", // invalid program length
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",       //Invalid program length for witness version 0 (per BIP141)
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",      // invalid padding
            "bc1gmk9yu",                                  // empty data section
        ];

        #[test]
        fn from_invalid_address() {
            INVALID.iter().for_each(|invalid_bech32| {
                assert_eq!(true, BitcoinAddress::<N>::from_str(invalid_bech32).is_err());
            });
        }

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &BitcoinFormat::Bech32);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &BitcoinFormat::Bech32);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::Bech32);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod bech32_testnet {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cVQmTtLoCjDJAXVj778xyww1ZbpJQt7Vq9sDt8Mdmw97Rg7TaNes",
                "tb1qmkvfprg8pkr3apv9gyykmhe26fexyla076ss0g",
            ),
            (
                "cTxHRG8MgrnSQstuMs5VnQcFBjrs67NmiJGo1kevnJDS7QFGLUAi",
                "tb1qfe0dnfpxp4c9lfdjzvmf5q72jg83emgknmcxxd",
            ),
            (
                "cSN1N2Vmhg9jPSUpXyQj8WbNUgeLHbC3Yj8SFX2N834YMepMwNZH",
                "tb1qx4jm2s3ks5vadh2ja3flsn4ckjzhdxmxmmrrzx",
            ),
            (
                "cMvmoqYYzr4dgzNZ22PvaqSnNx98evXc1b7m8FfK9SdCqhiWdP2c",
                "tb1ql0g42pusevlgd0jh9gyr32s0h0pe96wpnrqg3m",
            ),
            (
                "cVodD5ifcBjYVUs19GLwz6YzU2hUhdNagBx9QQcZp7TgjLuuFYn3",
                "tb1qwnh7hu5qfrjsk9pyn3vvmzr48v4l8kp4ug0txn",
            ),
        ];

        const INVALID: [&str; 3] = [
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", // invalid hrp
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", // Mixed case
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        ];

        #[test]
        fn from_invalid_address() {
            INVALID.iter().for_each(|invalid_bech32| {
                assert_eq!(true, BitcoinAddress::<N>::from_str(invalid_bech32).is_err());
            });
        }

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &BitcoinFormat::Bech32);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = BitcoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = BitcoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &BitcoinFormat::Bech32);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &BitcoinFormat::Bech32);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = BitcoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }
}

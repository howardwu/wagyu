use crate::address::ZcashAddress;
use crate::format::ZcashFormat;
use crate::librustzcash::algebra::curve::bls12_381::Bls12;
use crate::librustzcash::algebra::field::{PrimeField, PrimeFieldRepr};
use crate::librustzcash::sapling_crypto::{
    jubjub::{FixedGenerators, JubjubEngine, JubjubParams, ToUniform},
    primitives::ProofGenerationKey as SaplingProofGenerationKey,
};
use crate::librustzcash::zip32::prf_expand;
use crate::network::ZcashNetwork;
use crate::public_key::ZcashPublicKey;
use wagyu_model::{crypto::checksum, Address, AddressError, PrivateKey, PrivateKeyError, PublicKey};

use base58::{FromBase58, ToBase58};
use bech32::{Bech32, FromBase32, ToBase32};
use rand::Rng;
use secp256k1;
use std::{
    cmp::{Eq, PartialEq},
    fmt::{self, Debug, Display},
    io::{self, Read, Write},
    marker::PhantomData,
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct P2PKHSpendingKey<N: ZcashNetwork> {
    /// The ECDSA private key
    pub(super) secret_key: secp256k1::SecretKey,
    /// If true, the private key is serialized in compressed form
    pub(super) compressed: bool,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: ZcashNetwork> P2PKHSpendingKey<N> {
    pub fn new(secret_key: secp256k1::SecretKey, compressed: bool) -> Self {
        Self {
            secret_key,
            compressed,
            _network: PhantomData,
        }
    }

    /// Returns the p2pkh spending key (secp256k1 secret key)
    pub fn to_secp256k1_secret_key(&self) -> secp256k1::SecretKey {
        self.secret_key.clone()
    }

    /// Returns `true` if the p2pkh spending key is in compressed form.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}

impl<N: ZcashNetwork> Display for P2PKHSpendingKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        /// Returns a WIF string given a secp256k1 secret key.
        fn to_wif<N: ZcashNetwork>(secret_key: &secp256k1::SecretKey, compressed: bool) -> String {
            let mut wif = [0u8; 38];
            wif[0] = N::to_wif_prefix();
            wif[1..33].copy_from_slice(&secret_key[..]);

            if compressed {
                wif[33] = 0x01;
                let sum = &checksum(&wif[0..34])[0..4];
                wif[34..].copy_from_slice(sum);
                wif.to_base58()
            } else {
                let sum = &checksum(&wif[0..33])[0..4];
                wif[33..37].copy_from_slice(sum);
                wif[..37].to_base58()
            }
        }
        write!(f, "{}", to_wif::<N>(&self.secret_key, self.compressed))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct P2SHSpendingKey {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SproutSpendingKey<N: ZcashNetwork> {
    /// Raw encoding of (0000 || 252-bit a_sk)
    pub(super) spending_key: [u8; 32],
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: ZcashNetwork> SproutSpendingKey<N> {
    pub fn new(spending_key: [u8; 32]) -> Self {
        Self {
            spending_key,
            _network: PhantomData,
        }
    }
}

impl<N: ZcashNetwork> Display for SproutSpendingKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut spending_key = [0u8; 38];
        spending_key[0..2].copy_from_slice(&N::to_sprout_spending_key_prefix());
        spending_key[2..34].copy_from_slice(&self.spending_key);

        let sum = &checksum(&spending_key[0..34])[0..4];
        spending_key[34..].copy_from_slice(sum);

        write!(f, "{}", spending_key.to_base58())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SaplingOutgoingViewingKey(pub [u8; 32]);

#[derive(Clone)]
pub struct SaplingSpendingKey<N: ZcashNetwork> {
    /// Raw encoding of LEBS2OSP_256(sk)
    pub(super) spending_key: Option<[u8; 32]>,
    pub(super) ask: <Bls12 as JubjubEngine>::Fs,
    pub(super) nsk: <Bls12 as JubjubEngine>::Fs,
    pub(super) ovk: SaplingOutgoingViewingKey,
    pub(super) _network: PhantomData<N>,
}

impl<N: ZcashNetwork> SaplingSpendingKey<N> {
    pub fn from_spending_key(sk: &[u8; 32]) -> Self {
        let ask = <Bls12 as JubjubEngine>::Fs::to_uniform(prf_expand(sk, &[0x00]).as_bytes());
        let nsk = <Bls12 as JubjubEngine>::Fs::to_uniform(prf_expand(sk, &[0x01]).as_bytes());
        let mut ovk = SaplingOutgoingViewingKey([0u8; 32]);
        ovk.0.copy_from_slice(&prf_expand(sk, &[0x02]).as_bytes()[..32]);
        Self {
            spending_key: Some(*sk),
            ask,
            nsk,
            ovk,
            _network: PhantomData,
        }
    }

    pub fn proof_generation_key(&self, params: &<Bls12 as JubjubEngine>::Params) -> SaplingProofGenerationKey<Bls12> {
        SaplingProofGenerationKey {
            ak: params
                .generator(FixedGenerators::SpendingKeyGenerator)
                .mul(self.ask, params),
            nsk: self.nsk,
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut ask_repr = <<Bls12 as JubjubEngine>::Fs as PrimeField>::Repr::default();
        ask_repr.read_le(&mut reader)?;
        let ask = <Bls12 as JubjubEngine>::Fs::from_repr(ask_repr)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut nsk_repr = <<Bls12 as JubjubEngine>::Fs as PrimeField>::Repr::default();
        nsk_repr.read_le(&mut reader)?;
        let nsk = <Bls12 as JubjubEngine>::Fs::from_repr(nsk_repr)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut ovk = [0; 32];
        reader.read_exact(&mut ovk)?;

        Ok(Self {
            spending_key: None,
            ask,
            nsk,
            ovk: SaplingOutgoingViewingKey(ovk),
            _network: PhantomData,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.ask.into_repr().write_le(&mut writer)?;
        self.nsk.into_repr().write_le(&mut writer)?;
        writer.write_all(&self.ovk.0)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        self.write(&mut result[..])
            .expect("should be able to serialize an ExpandedSpendingKey");
        result
    }
}

impl<N: ZcashNetwork> Debug for SaplingSpendingKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SaplingSpendingKey {{ sk: {:?}, ask: {:?}, nsk: {:?}, ovk: {:?} }}",
            self.spending_key, self.ask, self.nsk, self.ovk
        )?;
        Ok(())
    }
}

impl<N: ZcashNetwork> Display for SaplingSpendingKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(spending_key) = self.spending_key {
            match Bech32::new(N::to_sapling_spending_key_prefix(), spending_key.to_base32()) {
                Ok(key) => write!(f, "{}", key.to_string())?,
                Err(_) => return Err(fmt::Error),
            }
        } else {
            let mut buffer = vec![0; 96];
            match self.write(buffer.as_mut_slice()).is_ok() {
                true => {
                    for s in &buffer[..] {
                        write!(f, "{:02x}", s)?;
                    }
                }
                false => return Err(fmt::Error),
            }
        }
        Ok(())
    }
}

impl<N: ZcashNetwork> PartialEq for SaplingSpendingKey<N> {
    fn eq(&self, other: &Self) -> bool {
        if let Some(this) = self.spending_key {
            if let Some(that) = other.spending_key {
                if this != that {
                    return false;
                }
            }
        }
        self.ask == other.ask && self.nsk == other.nsk && self.ovk == other.ovk
    }
}

impl<N: ZcashNetwork> Eq for SaplingSpendingKey<N> {}

/// Represents a Zcash private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZcashPrivateKey<N: ZcashNetwork> {
    /// P2PKH transparent spending key
    P2PKH(P2PKHSpendingKey<N>),
    /// P2SH transparent spending key
    P2SH(P2SHSpendingKey),
    /// Sprout shielded spending key
    Sprout(SproutSpendingKey<N>),
    /// Sapling shielded spending key
    Sapling(SaplingSpendingKey<N>),
}

impl<N: ZcashNetwork> PrivateKey for ZcashPrivateKey<N> {
    type Address = ZcashAddress<N>;
    type Format = ZcashFormat;
    type PublicKey = ZcashPublicKey<N>;

    /// Returns a randomly-generated compressed Zcash private key.
    fn new<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError> {
        Self::new_p2pkh(rng)
    }

    /// Returns the public key of the corresponding Zcash private key.
    fn to_public_key(&self) -> Self::PublicKey {
        ZcashPublicKey::<N>::from_private_key(self)
    }

    /// Returns the address of the corresponding Zcash private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        ZcashAddress::<N>::from_private_key(self, format)
    }
}

impl<N: ZcashNetwork> ZcashPrivateKey<N> {
    /// Returns a randomly-generated Zcash P2PKH private key.
    pub fn new_p2pkh<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError> {
        let random: [u8; 32] = rng.gen();
        let secret_key = secp256k1::SecretKey::from_slice(&random)?;
        Ok(ZcashPrivateKey::<N>::P2PKH(P2PKHSpendingKey::<N>::new(
            secret_key, true,
        )))
    }

    /// Returns a randomly-generated Zcash Sprout private key.
    pub fn new_sprout<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError> {
        let spending_key = SproutSpendingKey::<N>::new(rng.gen());
        Self::sprout(&spending_key.to_string())
    }

    /// Returns a randomly-generated Zcash Sapling private key.
    pub fn new_sapling<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError> {
        Self::sapling(&rng.gen())
    }

    /// Returns a P2PKH private key from a given WIF.
    fn p2pkh(wif: &str) -> Result<Self, PrivateKeyError> {
        let data = wif.from_base58()?;
        let len = data.len();
        if len != 37 && len != 38 {
            return Err(PrivateKeyError::InvalidCharacterLength(len));
        }

        let expected = &data[len - 4..][0..4];
        let checksum = &checksum(&data[0..len - 4])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(PrivateKeyError::InvalidChecksum(expected, found));
        }

        Ok(ZcashPrivateKey::<N>::P2PKH(P2PKHSpendingKey::<N>::new(
            secp256k1::SecretKey::from_slice(&data[1..33])?,
            len == 38,
        )))
    }

    /// Returns a Sprout private key from a given spending key.
    fn sprout(spending_key: &str) -> Result<Self, PrivateKeyError> {
        let data = spending_key.from_base58()?;
        let len = data.len();
        if len != 38 {
            return Err(PrivateKeyError::InvalidByteLength(len));
        }

        let expected = &data[len - 4..][0..4];
        let checksum = &checksum(&data[0..len - 4])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(PrivateKeyError::InvalidChecksum(expected, found));
        }

        let mut sk = [0u8; 32];
        sk.copy_from_slice(&data[2..34]);
        sk[0] &= 0x0f;

        Ok(ZcashPrivateKey::<N>::Sprout(SproutSpendingKey::<N>::new(sk)))
    }

    /// Returns a Sapling private key from a given seed.
    fn sapling(spending_key: &[u8; 32]) -> Result<Self, PrivateKeyError> {
        Ok(ZcashPrivateKey::<N>::Sapling(
            SaplingSpendingKey::<N>::from_spending_key(spending_key),
        ))
    }

    /// Returns a Sapling private key from a given expanded spending key.
    fn sapling_expanded(expanded_spending_key: &str) -> Result<Self, PrivateKeyError> {
        let data = hex::decode(expanded_spending_key)?;
        if data.len() != 96 {
            return Err(PrivateKeyError::InvalidByteLength(data.len()));
        }
        Ok(ZcashPrivateKey::<N>::Sapling(SaplingSpendingKey::<N>::read(&data[..])?))
    }
}

impl<N: ZcashNetwork> FromStr for ZcashPrivateKey<N> {
    type Err = PrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b58 = s.from_base58();
        let hex = hex::decode(s);
        let b32 = Bech32::from_str(s);

        if b58.is_ok() && hex.is_err() && b32.is_err() {
            let data = b58?;
            if data.len() != 37 && data.len() != 38 {
                return Err(PrivateKeyError::InvalidByteLength(data.len()));
            }

            let prefix = &data[0..2];

            // Sprout
            if prefix == N::to_sprout_spending_key_prefix() {
                return Self::sprout(s);
            }

            // Transparent
            // Check that the network byte correspond with the correct network.
            if N::from_wif_prefix(data[0]).is_ok() {
                return Self::p2pkh(s);
            }

            return Err(PrivateKeyError::UnsupportedFormat);
        }

        // Sapling expanded spending key
        if hex.is_ok() && b32.is_err() {
            let data = hex?;
            if data.len() == 96 {
                return Self::sapling_expanded(s);
            }
        }

        // Sapling spending key
        if b58.is_err() && b32.is_ok() {
            let key = b32?;
            let prefix = key.hrp();
            let spending_key: Vec<u8> = FromBase32::from_base32(key.data())?;

            if prefix == N::to_sapling_spending_key_prefix() {
                let mut key = [0u8; 32];
                key.copy_from_slice(&spending_key);
                return Self::sapling(&key);
            }
        }

        Err(PrivateKeyError::UnsupportedFormat)
    }
}

impl<N: ZcashNetwork> Display for ZcashPrivateKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            ZcashPrivateKey::<N>::P2PKH(p2pkh) => write!(f, "{}", p2pkh.to_string()),
            ZcashPrivateKey::<N>::Sprout(sprout) => write!(f, "{}", sprout.to_string()),
            ZcashPrivateKey::<N>::Sapling(sapling) => write!(f, "{}", sapling.to_string()),
            _ => write!(f, ""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;

    fn test_to_public_key<N: ZcashNetwork>(expected_public_key: &ZcashPublicKey<N>, private_key: &ZcashPrivateKey<N>) {
        let public_key = private_key.to_public_key();
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address<N: ZcashNetwork>(
        expected_address: &ZcashAddress<N>,
        expected_format: &ZcashFormat,
        private_key: &ZcashPrivateKey<N>,
    ) {
        let address = private_key.to_address(expected_format).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_str<N: ZcashNetwork>(
        expected_private_key: &ZcashPrivateKey<N>,
        expected_public_key: &str,
        expected_address: &str,
        expected_format: &ZcashFormat,
        seed: &str,
    ) {
        let private_key = ZcashPrivateKey::<N>::from_str(seed).unwrap();
        assert_eq!(*expected_private_key, private_key);
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(
            expected_address,
            private_key.to_address(expected_format).unwrap().to_string()
        );
    }

    fn test_to_str<N: ZcashNetwork>(expected_private_key: &str, private_key: &ZcashPrivateKey<N>) {
        assert_eq!(expected_private_key, private_key.to_string());
    }

    fn test_invalid_spending_key_length<N: ZcashNetwork>(spending_key: &str) {
        let length = spending_key.len();
        let first = &spending_key[0..=0];

        assert!(ZcashPrivateKey::<N>::from_str("").is_err());
        assert!(ZcashPrivateKey::<N>::from_str(first).is_err());
        assert!(ZcashPrivateKey::<N>::from_str(&spending_key[0..(length / 2)]).is_err());
        assert!(ZcashPrivateKey::<N>::from_str(&spending_key[0..(length - 1)]).is_err());
        assert!(ZcashPrivateKey::<N>::from_str(&format!("{}{}", spending_key, first)).is_err());
        assert!(ZcashPrivateKey::<N>::from_str(&format!("{}{}", spending_key, spending_key)).is_err());
    }

    fn test_invalid_checksum<N: ZcashNetwork>(spending_key: &str) {
        let length = spending_key.len();
        let mut s = String::from(spending_key);
        s.replace_range((length - 4).., "AAAA");

        assert!(ZcashPrivateKey::<N>::from_str(&s).is_err())
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "L3a3yRcYATnZQt7ams14Pe5KCyRzrrCSejDyeQzHXGntToffVH4g",
                "0310d63f8c2f0a6efd13ce8a77776de26eba1816f73aa73e73a4da3f2368fcc949",
                "t1JwBjJWgNQVqWxGha2RsPZMhVGgfRg2pod",
            ),
            (
                "Kx7f3xE2TmhczSkFUxxSajE2vuuLrrqinAbTZBxqxHj6XGbhoyrQ",
                "02f4bf56c9c8389b04752236a4f2419367e3a4e36fe80da6162a0b530ca91262b0",
                "t1VnZLVwvaUsnYt34XJHNTu24wn3kD8RwsE",
            ),
            (
                "L46n9WGR671oANndbkxBBz9orQ36TQu98zeRJmp41tqk3HM6UpJk",
                "031347c183c608c629e8bc0ad76718cc9f2a1ee9e53d45862a1b9c8fad25f8ab5b",
                "t1N8HuTxFm9qS7yQCi3TsMGCQ8kPPTx5Me7",
            ),
            (
                "L2AMjT43hZQGATgtkakVMMMEguoJLwDAcZJVg1zsqjWeWaC4cTVd",
                "03a0d8ab54a080f6e085777c2f5432b22b3543ad421aecc3f2136bcd2e1e2a59e4",
                "t1PUKYyoqPZw43CHqjquU9PZE1GEvmHNbPa",
            ),
            (
                "L53GxzD5rVaX6jY5ig1qNBqur5WyAeFn8sCo9VwU4J717ewDbgc6",
                "020ceda15424ec7159f7ac5f6ad2654c93ab4cae7f9419de7aae39967f97907fd7",
                "t1TqidZPmPSJsr1wcMuYwDDaa7D9ow5sWMx",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::<N>::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &ZcashFormat::P2PKH, &private_key);
            });
        }

        #[test]
        fn from() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str(
                        &expected_private_key,
                        expected_public_key,
                        expected_address,
                        &ZcashFormat::P2PKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn invalid_spending_key_length() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_spending_key_length::<N>(private_key);
            });
        }

        #[test]
        fn invalid_checksum() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_checksum::<N>(private_key);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "5JkYwYTFDzd41Uy3qB8ucvENFzFBYHnZGk7GbFnHTwUaepikxpJ",
                "0471b47908e7a0cd0e053129cde9a38c54730bc63faf780efc4f9b7c3db4ed1b7db0f877ae0e1959d2353bca05bc405fa1c48e76fec3e99c26e48c95cf112dc7c9",
                "t1Rxy8Qw6eXxSRFLwS3S1D8T436eR4zQTKp"
            ),
            (
                "5JBCdxHg7w5gDNVi4G34zHWNMqvPheZAG4TeQcwk5jgh7RcenAZ",
                "049af1ad996f0ca009bc2e7bcdb4a899f822dfca068dfabf8aa7fb2be86c5c3cf198efbdfb3c870b01c81e3236e0dd4db0fe279a31695ce17cc83b94fe85d250ab",
                "t1PpkWq8MVDcpG7mneEhgmVZnkpM1vQQJdx"
            ),
            (
                "5JQjtXVXkf1trwNCPK9KsUapYDrwKUYnPZwX5zFdfy7DiFfEv2g",
                "0487dbab62116ed483bec0d8f4422e1ab315e65b8f981f6e4bd17621e393c8e7632b4028807695d959691d2e121a8e953c47e618defa6e9c159f7fdf60870981c5",
                "t1PsCpuxCMZ44j3H5tuTLmdPKqdhR3N4TPf"
            ),
            (
                "5Kht325G1JErVxAKcM7WreWR9oVgwsN21m4VVoVKiJ4vAm9mLZQ",
                "04463f48d8b3d7e622900633cd409f851c49fec6607eba3db52965995b300e8abaea439a2d5bd6f6b86a53198eac8d2735a4b013f8a811e1b151fdb5b5f11c595d",
                "t1XDKPwTpFS2BWWXASnhTLKWfoaFocRGErk"
            ),
            (
                "5KA9KkgmBfSUiRqBdsjiAjRzcQbGcYD5EpWArFfNRsw1h4bwmqU",
                "04315a06c80dd5886e960b213fdefd9df76fa2b26f9e3e876a72160a20af1fea95425c12d5c5ed75e89a564a4bdcdf5fbb197e29b2b042016987f2eaf64b26d5f3",
                "t1Zk2uJgGLZCJCRXUYUGTpRqqn3utqsdPsg"
            )
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::<N>::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &ZcashFormat::P2PKH, &private_key);
            });
        }

        #[test]
        fn from() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str(
                        &expected_private_key,
                        expected_public_key,
                        expected_address,
                        &ZcashFormat::P2PKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn invalid_spending_key_length() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_spending_key_length::<N>(private_key);
            });
        }

        #[test]
        fn invalid_checksum() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_checksum::<N>(private_key);
            });
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "cNG7sM13VvGrhKgepLeEiiQAERXpGB6j5NuRwhh6sLh2skMTQf7M",
                "02d327c40e543a08c17cda94d0b9660520bd075151280e487294e94eced3a283df",
                "tmWT3bvWCHQkAXXucPjWHqLs9EyWUDdzSuN",
            ),
            (
                "cQXFXQHBzCuPbKYdeKERGeMrh8TJAsos7TLYDamQLXJiXY9sUkY6",
                "038a2754d1b25a7d0cb3518ea92ca07de0fc21a56d920be6ca10857893c48989fb",
                "tmAs578aq6jaXqmnXRrhWpjJsySFf7eXb5J",
            ),
            (
                "cQNALaabLLxMzdBkbCZvcTJtyvQ5zg4UhhskMk5R8Wu1ymSXCLsX",
                "0309341fa999f0f2951eb9867f84b55781904fe2228b8ffc8dc1a8a47e1c357957",
                "tmD8R6k2mTfTwGG24w5SBeAwQnqKGFx3cSg",
            ),
            (
                "cS6qPDRjncjCAe95SGKH81491NGkwzWqhAsGTEzkgVNC6ZdBpB4M",
                "024e12c05184403e0243a1563b9ebaeda7b529bf1306abe55827d363697be936a4",
                "tmPNWe7d4Hvkh4TEZ6Xd1ZQBje7VNQQ2Anb",
            ),
            (
                "cRRjNZuyYu8aiqVLRLvj7PqTWKLELK2N257AgSvmPzMjfJ44oWtb",
                "03d08c6748dcad37dbcad05d4cde25234107785a1c19b6edda8bfc199c91877d7d",
                "tmRdRE5JAX6KX3c11GVgqc5R6JBRtfbuk8i",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::<N>::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &ZcashFormat::P2PKH, &private_key);
            });
        }

        #[test]
        fn from() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str(
                        &expected_private_key,
                        expected_public_key,
                        expected_address,
                        &ZcashFormat::P2PKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn invalid_spending_key_length() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_spending_key_length::<N>(private_key);
            });
        }

        #[test]
        fn invalid_checksum() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_checksum::<N>(private_key);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "92VN8AQdnRoBRw7QQcpUYsh1bSEWUrkZ364fjMUdNrm8fTJhEGw",
                "04d7d44136ec02643e813d1182256508622385d18052bf13ec475ce226d161d7832cb4f7032e900ccfc07f3a4870a1522f7b4ce381bc1f8c0bcc5d36ec3c9d351a",
                "tmCrh5cZDv5KUpcmbYzoaC4SZUTTbeoERdX"
            ),
            (
                "92cPhKtH4PfSsJBihSvd5aeZXU5gvzJWM2pHVWZ4dgYtioLb5Vm",
                "0414e08f6a2fa6b0cc205aef1be0c8e87dbcc312f72c46e2446441c0e42fb51b20982678deade96a1851f4f673774fd834b8a18ccae6aef65fe53098ad533ee944",
                "tmEev5ommgX8J1E2cgygciUtB6BkAX3CYWc"
            ),
            (
                "921RfpWAirU31BCKn8LhctV3hF3EJCVGDok5jZGYhoNc5Cp8TxZ",
                "0408d8331b48fe348e7657f0cdbbd8027c715dabd62d9a94d6a028b9a5a972fc22548948c11eddb61f90a5da9a7647f4e4c2859def91ac45c1cea8f38817f9129e",
                "tmVttNTD4jkGikWYpmCmCCmtYk7s3EBTcGw"
            ),
            (
                "92nYXXcwdSZSykBUuRJUsGCeQQn1GimuDp3dfThsr1oVFft7mJR",
                "0433287b651e3df0d7fd32494673f7aaf5dabe9e4e9e9c292a4c4f2aab3b68845648a657ae274013e363ce89ab7f938ded9e3df1ef66fb0aadf7e41b823d8e3d34",
                "tmTSQ5RKyeND95C39kg8uJA9H1qD1WXvfQf"
            ),
            (
                "92t16UPRvwotFBR3CQfc9TweC5dqPiNwiaLSZLhbtGZkLM4RYpG",
                "042b9da4fe2356a93d83cf43e0c2b1714193ae9ad3ffd9cbfe3d1bd3ec6540345199ad024df690f8ffa1fe57ae675d14a510a919625aedf3442c3e2e4b43ff0683",
                "tmAhSm3UDLkKhZUAcAz4W83hmC4sgWS3zwk"
            )
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::<N>::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &ZcashFormat::P2PKH, &private_key);
            });
        }

        #[test]
        fn from() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str(
                        &expected_private_key,
                        expected_public_key,
                        expected_address,
                        &ZcashFormat::P2PKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn invalid_spending_key_length() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_spending_key_length::<N>(private_key);
            });
        }

        #[test]
        fn invalid_checksum() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_checksum::<N>(private_key);
            });
        }
    }

    mod sprout_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "SKxt8pwrQipUL5KgZUcBAqyLj9R1YwMuRRR3ijGMCwCCqchmi8ut",
                "ZiVKYQyUcyAJLKwcosSeDxkGRhygFdAPWsr3m8UgjC5X85yqNyLTtJJJYNH83Wf2AQKU6TZsd65MXBZLFj6eSCAFcnCFuVCFS",
                "zcJLC7a3aRJohMNCVjSZQ8jFuofhAHJNAY4aX5soDkYfgNejzKnEZbucJmVibLWCwK8dyyfDhNhf3foXDDTouweC382LcX5",
            ),
            (
                "SKxoo5QkFQgTbdc6EWRKyHPMdmtNDJhqudrAVhen9b4kjCwN6CeV",
                "ZiVKfdhhmQ1fpXaxyW5zRXw4Dhg9cbKRgK7mNFoBLiKjiBZiHJYJTpV2gNMDMPY9sRC96vnKZcnTMSi65SKPyL4WNQNm9PT5H",
                "zcRYvLiURno1LhXq95e8avXFcH2fKKToSFfhqaVKTy8mGH7i6SJbfuWcm4h9rEA6DvswrbxDhFGDQgpdDYV8zwUoHvwNvFX",
            ),
            (
                "SKxsVGKsCESoVb3Gfm762psjRtGHmjmv7HVjHckud5MnESfktUuG",
                "ZiVKkMUGwx4GgtwxTedRHYewVVskWicz8APQgdcYmvUsiLYgSh3cLAa8TwiR3shyNngGbLiUbYMkZ8F1giXmmcED98rDMwNSG",
                "zcWGguu2UPfNhh1ygWW9Joo3osvncsuehtz5ewvXd78vFDdnDCRNG6QeKSZpwZmYmkfEutPVf8HzCfBytqXWsEcF2iBAM1e",
            ),
            (
                "SKxp72QGQ2qtovHSoVnPp8jRFQpHBhG1xF8s27iRFjPXXkYMQUA6",
                "ZiVKkeb8STw7kpJQsjRCQKovQBciPcfjkpajuuS25DTXSQSVasnq4BkyaMLBBxAkZ8fv6f18woWgaA8W7kGvYp1C1ESaWGjwV",
                "zcWZomPYMEjJ49S4UHcvTnhjYqogfdYJuEDMURDpbkrz94bkzdTdJEZKWkkpQ8nK62eyLkZCvLZDFtLC2Cq5BmEK3WCKGMN",
            ),
            (
                "SKxpmLdykLu3xxSXtw1EA7iLJnXu8hFh8hhmW1B2J2194ijh5CR4",
                "ZiVKvpWQiDpxAvWTMLkjjSbCiBGc4kXhtkgAJfW1JVbCTUY4YaAVvVZzCz6wspG9qttciRFLEXm3HLQAmssFbUp9uPEkP3uu5",
                "zcgjj3fJF59QGBufopx3F51jCjUpXbgEzec7YQT6jRt4Ebu5EV3AW4jHPN6ZdXhmygBvQDRJrXoZLa3Lkh5GqnsFUzt7Qok",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &ZcashFormat::Sprout, &private_key);
            });
        }

        #[test]
        fn from() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str(
                        &expected_private_key,
                        expected_public_key,
                        expected_address,
                        &ZcashFormat::Sprout,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn invalid_spending_key_length() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_spending_key_length::<N>(private_key);
            });
        }

        #[test]
        fn invalid_checksum() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_checksum::<N>(private_key);
            });
        }
    }

    mod sapling_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "secret-spending-key-main1hd5umd08pc4m6f8hw8x3tgv26kxn4w0p4g72kxrtndjazlm64hhsnczrtx",
                "zviews16ggk069w3n9u6d8edmzchhme3jnejssh6qupyyqw48ju6ns4jm8r508jkmrr93zank3mpszymqn9t95lw9jj2plwhuj72pzgddlm3e90e8c73nmt36hp3duxa3uayxxs588ljz6ryul2zck6nx5a9csalupjg0s0",
                "zs1dq9dlh6u6hna0u96aqtynxt3acddtgkgdx4re65500nmc2aze0my65ky36vaqvj4hkc9ut66eyf"
            ),
            (
                "275043030be0d6106d40077090821249cb94973266f8058a390c1a123df9b108fbd3af756453d58e31ff2a8f3c621767c57bbcf3a0127b15b73cb7237a48da0bafc9f1e8cf6b8eae18b786ec79d218d0a1cff90b43273ea162da99a9d2e21dff",
                "zviews16ggk069w3n9u6d8edmzchhme3jnejssh6qupyyqw48ju6ns4jm8r508jkmrr93zank3mpszymqn9t95lw9jj2plwhuj72pzgddlm3e90e8c73nmt36hp3duxa3uayxxs588ljz6ryul2zck6nx5a9csalupjg0s0",
                "zs1dq9dlh6u6hna0u96aqtynxt3acddtgkgdx4re65500nmc2aze0my65ky36vaqvj4hkc9ut66eyf"
            ),
            (
                "secret-spending-key-main1pj046u8243rgvg2s4clj5nhvc6r48fe9vl4kvggdlrsc4y2ztt0skswpn9",
                "zviews1hvk56ls9kxhmdp48unta36p2tyhjtvnv4fu2qm5nnc80sdwxzqx88rvf5ckz4nvknmcudrt8m8fktvnhz3wvvz5wjhs3x90pj2ezc20kzfrka2265t2t0h6m3qwrvwpfkwwv4f3333kl80ft5cn559075qt2lj8x",
                "zs1akf8swew32rr4n63qedewhp2yz3wcjeazp6efs82lgealmux0h30ayju440rqyuscdr3wd5yuap"
            ),
            (
                "secret-spending-key-main1ls0d46g5d4w8lyucsudvpyyhl6nvzkf733ak7vuy4um0l8xrkthqnh9a7d",
                "zviews16cgwcgd6ppxpkn6za8pcam7wrhaltsyy8f2f6z94zxgqwazmzuwmg694svru6tr72nk7xdxyaxze8cshwczraz2kws93qfgncq7tqgesr2gn8mjehqnpgvcykpqa3c0j78u36d394476e8jv3rnrpfmd3525eysp",
                "zs14q3vapgrd6wfs9pr7hfy37y9djm3gnq09ztxsqs2x2vzv0lck978843q8r2ysejgwp9mcx7ws48"
            ),
            (
                "secret-spending-key-main1vqu0tez5nryjah27dgjc30xw0096cczwf6p9aecpt5glx0g7jees99g9fe",
                "zviews1npr6zhenjwkcjg0jk2pwxqeafzkm96hfg403u6mhqw97jylqf3gev7mdknmjdlppc470w0fur7k86pzter4zckn4xd85vsw33ukscye4ezz2fpflws8f8e2a0wd8hqh8mrrdz7erq55zzse4nqrl945s6yx2ttmj",
                "zs1rzjhudlm99h5fyrh7dfsvkfg9l5z587w97pm3ce9hpwfxpgck6p55lwu5mcapz7g3r40y597n2c"
            )
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::<N>::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &address.to_format(), &private_key);
            });
        }

        #[test]
        fn from() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str(
                        &expected_private_key,
                        expected_public_key,
                        expected_address,
                        &ZcashFormat::Sapling(Some(ZcashAddress::<N>::get_diversifier(expected_address).unwrap())),
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn invalid_spending_key_length() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_spending_key_length::<N>(private_key);
            });
        }
    }

    mod sapling_testnet {
        use super::*;

        type N = Testnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "secret-spending-key-test1fygsm6l3ltqqs63040tq426p85pgzuetdeg6q0wka38nx3rfa70sa9qp0v",
                "zviewtestsapling1xh2u7cdrmr8nq7q3y6furqu6zsc8z7gq36jlpypgzrgrujs9mz73jsff72uzmm22juadyj4runvwfxssuqul2psxz6vp2ywk4zyv4rk2v65py6tkzt7rr7jwpy52c9z28yud27fmakss7agnu9dxl9ddsqjvgydw",
                "ztestsapling1jzzt7gjscav7lmdpemknv0v8rmmdzpcaqrx95azrgaky94drrvf0fg4wlnlkaclqj3r3s23g2sf"
            ),
            (
                "secret-spending-key-test1f6w469xhw65naz4pm4lxnmd8em7ev5ddzszy8js325lr0xe2ay9snuw9t5",
                "zviewtestsapling1hr66pwzsmdjzfdcyurk6n5q773e0ckxaz5vukc9f0kfyqeq7zp0gs4hqvtdfcu5mkdvqkex9mye3jzhcvpnw2xyj9eukwf2hgmqzf6jtcyhjayhe8a8c2vtpham5lexecvjczqsvnnzjaepzzmyw2aw5hvg4f7pf",
                "ztestsapling19epsvtxnzf59pr993fq4g0gu0fmrn2jl2z9jm2lgj3220c7r9shyvcpe25ul7wxvzk60z82zyf7"
            ),
            (
                "secret-spending-key-test1s4zwnn7xgglz9099kc4l2ejfl5m3ddkvpy3erm960raszl2lakss48u07t",
                "zviewtestsapling1wkmzxw7jj926xc0v92v92t6urhw76t750tugp4u28untfn5vctfxyqyw855sf0ltvx4akuzr9ps0hej40fqxcxh89f9zqnlfxjv9z9kdlq84k5hmclfzctwkxzfekajpemrkktj03mmdc5e8d6jt8m7p4ycfqv6s",
                "ztestsapling18ur694qcm6w657u9xt8aekutn98gyvpzwzjgjz99594x775ppeze5vwnp2ndw0u205vkuh2tqcu"
            ),
            (
                "secret-spending-key-test1d5seqlm269xjsgmz2qmwp9g683tx6n0hkyqalv5fjyraqt5mmz7snwyhek",
                "zviewtestsapling1udd09lafca6g9cganxxssayja8uqvuj4sff77vxakmt394g6f2kvtpz4xjwv6klqmedftpx0uca9helgd6ulyruwlvlmrmuymr7xvfd28res3hn9vum0k6czj2wkjkaeqsgg6kmgp9fvua6wjw9nc5zp3vrv2zlu",
                "ztestsapling1hkyeldalqna6kxzkkpc3gl4yvtd842sld4kkx7mhtm4srhndnqm347q7x672t05j245skqsctvs"
            ),
            (
                "secret-spending-key-test1mqq09wgeevr0wwt2ncjncalktcwtt7tjxuk2cxtwce2xuzf4t0lqf5jn03",
                "zviewtestsapling1rwnkhka5qdkc2ezk9enxftued3f7a02l6qsf39xezqxketel69ymkf2szcw2zfxxwttat5khlk0mhks5y0jftp0j95nf7kvf33vwt002gwcnmas7e4kdy0np2x588et4mwd4ffp7zlx4ky4yqmmwnkmqwvupsy6f",
                "ztestsapling12n4jm24lflgmjk4crm0322p0gpmww98v5cqyurphq6tr4r4q9kxyz2f3tp9x92mm8kruwwg2u5w"
            )
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::<N>::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &address.to_format(), &private_key);
            });
        }

        #[test]
        fn from() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str(
                        &expected_private_key,
                        expected_public_key,
                        expected_address,
                        &ZcashFormat::Sapling(Some(ZcashAddress::<N>::get_diversifier(expected_address).unwrap())),
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn invalid_spending_key_length() {
            KEYPAIRS.iter().for_each(|(private_key, _, _)| {
                test_invalid_spending_key_length::<N>(private_key);
            });
        }
    }
}

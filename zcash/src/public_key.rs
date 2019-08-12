use crate::address::{Format, ZcashAddress};
use crate::librustzcash::algebra::curve::bls12_381::Bls12;
use crate::librustzcash::sapling_crypto::{
    jubjub::{edwards, FixedGenerators, JubjubBls12, JubjubEngine, JubjubParams, Unknown},
    primitives::ViewingKey as SaplingViewingKey,
};
use crate::librustzcash::JUBJUB;
use crate::network::ZcashNetwork;
use crate::private_key::{SaplingOutgoingViewingKey, SaplingSpendingKey, ZcashPrivateKey};
use wagyu_model::{crypto::checksum, Address, AddressError, PublicKey, PublicKeyError};

use base58::{FromBase58, ToBase58};
use bech32::{Bech32, FromBase32, ToBase32};
use byteorder::{BigEndian, ByteOrder};
use crypto::sha2::sha256_digest_block;
use secp256k1;
use std::cmp::{Eq, PartialEq};
use std::marker::PhantomData;
use std::str::FromStr;
use std::{fmt, fmt::Display};
use std::io::{self, Read, Write};

static H256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct P2PKHViewingKey {
    /// The ECDSA public key
    pub(super) public_key: secp256k1::PublicKey,
    /// If true, the public key is serialized in compressed form
    pub(super) compressed: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct P2SHViewingKey {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SproutViewingKey {
    pub key_a: [u8; 32],
    pub key_b: [u8; 32],
}

impl SproutViewingKey {
    /// Returns a sprout public key corresponding to a sprout private key
    pub fn from_sprout_spending_key(spending_key: &[u8; 32]) -> SproutViewingKey {
        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];

        Self::prf(&mut key_a, &spending_key, 0);
        Self::prf(&mut key_b, &spending_key, 1);
        key_b[0] &= 248;
        key_b[31] &= 127;
        key_b[31] |= 64;

        SproutViewingKey { key_a, key_b }
    }

    /// Returns output of pseudorandom function
    fn prf(result: &mut [u8; 32], payload: &[u8; 32], t: u8) {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(payload);
        buf[0] = 0xc0 | (buf[0] & 0x0f);
        buf[32] = t;

        let mut state = H256;
        sha256_digest_block(&mut state, &buf);
        BigEndian::write_u32_into(&state, result);
    }
}

#[derive(Debug)]
pub struct SaplingFullViewingKey<N: ZcashNetwork> {
    pub(super) vk: SaplingViewingKey<Bls12>,
    pub(super) ovk: SaplingOutgoingViewingKey,
    pub(super) _network: PhantomData<N>
}

impl<N: ZcashNetwork> SaplingFullViewingKey<N> {
    pub fn from_spending_key(key: &SaplingSpendingKey<N>, params: &<Bls12 as JubjubEngine>::Params) -> Self {
        Self {
            vk: SaplingViewingKey {
                ak: params
                    .generator(FixedGenerators::SpendingKeyGenerator)
                    .mul(key.ask, params),
                nk: params
                    .generator(FixedGenerators::ProofGenerationKey)
                    .mul(key.nsk, params),
            },
            ovk: key.ovk,
            _network: PhantomData
        }
    }

    pub fn read<R: Read>(mut reader: R, params: &<Bls12 as JubjubEngine>::Params) -> io::Result<Self> {
        let ak = edwards::Point::<Bls12, Unknown>::read(&mut reader, params)?;
        let ak = match ak.as_prime_order(params) {
            Some(p) => p,
            None => return Err(io::Error::new(io::ErrorKind::InvalidData, "ak not in prime-order subgroup"))
        };
        if ak == edwards::Point::zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ak not of prime order"));
        }

        let nk = edwards::Point::<Bls12, Unknown>::read(&mut reader, params)?;
        let nk = match nk.as_prime_order(params) {
            Some(p) => p,
            None => return Err(io::Error::new(io::ErrorKind::InvalidData, "nk not in prime-order subgroup"))
        };

        let mut ovk = [0; 32];
        reader.read_exact(&mut ovk)?;

        Ok(Self {
            vk: SaplingViewingKey { ak, nk },
            ovk: SaplingOutgoingViewingKey(ovk),
            _network: PhantomData
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.vk.ak.write(&mut writer)?;
        self.vk.nk.write(&mut writer)?;
        writer.write_all(&self.ovk.0)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        self.write(&mut result[..]).expect("should be able to serialize a FullViewingKey");
        result
    }
}

impl<N: ZcashNetwork> PartialEq for SaplingFullViewingKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.vk.ak == other.vk.ak
            && self.vk.nk == other.vk.nk
            && self.ovk == other.ovk
    }
}

impl<N: ZcashNetwork> Eq for SaplingFullViewingKey<N> {}

impl<N: ZcashNetwork> Clone for SaplingFullViewingKey<N> {
    fn clone(&self) -> Self {
        Self {
            vk: SaplingViewingKey {
                ak: self.vk.ak.clone(),
                nk: self.vk.nk.clone(),
            },
            ovk: self.ovk.clone(),
            _network: PhantomData
        }
    }
}

/// Represents a Zcash public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZcashPublicKey<N: ZcashNetwork> {
    /// P2PKH transparent viewing key
    P2PKH(P2PKHViewingKey),
    /// P2SH transparent viewing key
    P2SH(P2SHViewingKey),
    /// Sprout shielded viewing key
    Sprout(SproutViewingKey),
    /// Sapling shielded viewing key
    Sapling(SaplingFullViewingKey<N>),
}

impl<N: ZcashNetwork> PublicKey for ZcashPublicKey<N> {
    type Address = ZcashAddress<N>;
    type Format = Format;
    type PrivateKey = ZcashPrivateKey<N>;

    /// Returns the public key corresponding to the given private key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        match private_key {
            // Transparent Public Key
            ZcashPrivateKey::<N>::P2PKH(spending_key) => ZcashPublicKey::<N>::P2PKH(P2PKHViewingKey {
                    public_key: secp256k1::PublicKey::from_secret_key(
                        &secp256k1::Secp256k1::new(),
                        &spending_key.secret_key,
                    ),
                    compressed: spending_key.compressed,
                }),
            // Transparent Multisignature
            ZcashPrivateKey::<N>::P2SH(_) => ZcashPublicKey::<N>::P2SH(P2SHViewingKey {}),
            // Sprout Viewing Key
            ZcashPrivateKey::<N>::Sprout(spending_key) => ZcashPublicKey::<N>::Sprout(SproutViewingKey::from_sprout_spending_key(&spending_key.spending_key)),
            // Sapling Full Viewing Key
            ZcashPrivateKey::<N>::Sapling(spending_key) => ZcashPublicKey::<N>::Sapling(SaplingFullViewingKey::from_spending_key(
                    &spending_key,
                    &JUBJUB,
                )),
        }
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl<N: ZcashNetwork> FromStr for ZcashPublicKey<N> {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        match public_key.len() {
            66 | 130 => Ok(ZcashPublicKey::<N>::P2PKH(P2PKHViewingKey {
                    public_key: secp256k1::PublicKey::from_str(public_key)?,
                    compressed: public_key.len() == 66,
                })
            ),
            97 => {
                let data = public_key.from_base58()?;
                let prefix = &data[..3];

                if prefix != N::to_sprout_viewing_key_prefix() {
                    return Err(PublicKeyError::InvalidPrefix(prefix.to_base58()));
                }

                let mut key_a = [0u8; 32];
                let mut key_b = [0u8; 32];

                key_a.copy_from_slice(&data[3..35]);
                key_b.copy_from_slice(&data[35..67]);

                Ok(ZcashPublicKey::<N>::Sprout(SproutViewingKey { key_a, key_b }))
            }
            167 | 177 => {
                let key = Bech32::from_str(public_key)?;
                let prefix = key.hrp();
                let viewing_key: Vec<u8> = FromBase32::from_base32(key.data())?;

                if prefix == N::to_sapling_viewing_key_prefix() {
                    let mut key = [0u8; 96];
                    key.copy_from_slice(&viewing_key);

                    Ok(ZcashPublicKey::<N>::Sapling(SaplingFullViewingKey::read(&key[..], &JubjubBls12::new())?))
                } else {
                    Err(PublicKeyError::InvalidPrefix(prefix.into()))
                }
            }
            _ => Err(PublicKeyError::InvalidCharacterLength(public_key.len())),
        }
    }
}

impl<N: ZcashNetwork> Display for ZcashPublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            ZcashPublicKey::<N>::P2PKH(p2pkh) => {
                if p2pkh.compressed {
                    for s in &p2pkh.public_key.serialize()[..] {
                        write!(f, "{:02x}", s)?;
                    }
                } else {
                    for s in &p2pkh.public_key.serialize_uncompressed()[..] {
                        write!(f, "{:02x}", s)?;
                    }
                }
            }
            ZcashPublicKey::<N>::Sprout(sprout) => {
                let mut data = [0u8; 71];
                data[..3].copy_from_slice(&N::to_sprout_viewing_key_prefix());
                data[3..35].copy_from_slice(&sprout.key_a);
                data[35..67].copy_from_slice(&sprout.key_b);

                let sum = &checksum(&data[0..67])[0..4];
                data[67..].copy_from_slice(sum);

                write!(f, "{}", data.to_base58())?
            }
            ZcashPublicKey::<N>::Sapling(sapling) => {
                let key = sapling.to_bytes().to_vec();
                match Bech32::new(N::to_sapling_viewing_key_prefix(), key.to_base32()) {
                    Ok(key) => write!(f, "{}", key.to_string())?,
                    Err(_) => return Err(fmt::Error),
                }
            }
            _ => (),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;

    fn test_from_private_key<N: ZcashNetwork>(
        expected_public_key: &ZcashPublicKey<N>,
        private_key: &ZcashPrivateKey<N>,
    ) {
        let public_key = ZcashPublicKey::<N>::from_private_key(private_key);
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address<N: ZcashNetwork>(
        expected_address: &ZcashAddress<N>,
        expected_format: &Format,
        public_key: &ZcashPublicKey<N>,
    ) {
        let address = public_key.to_address(expected_format).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_str<N: ZcashNetwork>(expected_public_key: &str, expected_address: &str, expected_format: &Format) {
        let public_key = ZcashPublicKey::<N>::from_str(expected_public_key).unwrap();
        let address = public_key.to_address(expected_format).unwrap();
        assert_eq!(expected_public_key, public_key.to_string());
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format());
    }

    fn test_to_str<N: ZcashNetwork>(expected_public_key: &str, public_key: &ZcashPublicKey<N>) {
        assert_eq!(expected_public_key, public_key.to_string());
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let expected_address = ZcashAddress::<N>::from_str(address).unwrap();
                let public_key = ZcashPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(&expected_address, &Format::P2PKH, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, &Format::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let expected_address = ZcashAddress::<N>::from_str(address).unwrap();
                let public_key = ZcashPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(&expected_address, &Format::P2PKH, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, &Format::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let expected_address = ZcashAddress::<N>::from_str(address).unwrap();
                let public_key = ZcashPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(&expected_address, &Format::P2PKH, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, &Format::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let expected_address = ZcashAddress::<N>::from_str(address).unwrap();
                let public_key = ZcashPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(&expected_address, &Format::P2PKH, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, &Format::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            })
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let expected_address = ZcashAddress::from_str(address).unwrap();
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                test_to_address(&expected_address, &Format::Sprout, &public_key);
            })
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, &Format::Sprout);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let expected_address = ZcashAddress::<N>::from_str(address).unwrap();
                let public_key = ZcashPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(
                    &expected_address,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(address).unwrap())),
                    &public_key,
                );
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(
                    expected_public_key,
                    expected_address,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(expected_address).unwrap())),
                );
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let expected_address = ZcashAddress::<N>::from_str(address).unwrap();
                let public_key = ZcashPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(
                    &expected_address,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(address).unwrap())),
                    &public_key,
                );
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(
                    expected_public_key,
                    expected_address,
                    &Format::Sapling(Some(ZcashAddress::<N>::get_diversifier(expected_address).unwrap())),
                );
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
        }
    }

    #[test]
    fn test_p2pkh_invalid() {
        type N = Mainnet;

        // Invalid public key length

        let public_key = "0";
        assert!(ZcashPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44";
        assert!(ZcashPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db";
        assert!(ZcashPublicKey::<N>::from_str(public_key).is_err());

        let public_key =
            "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5039ed714bf521e96e3f3609b74da898e44";
        assert!(ZcashPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5";
        assert!(ZcashPublicKey::<N>::from_str(public_key).is_err());
    }
}

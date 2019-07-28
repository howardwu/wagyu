use crate::address::{Format, ZcashAddress};
use crate::network::ZcashNetwork;
use crate::private_key::{SpendingKey, ZcashPrivateKey};
use wagu_model::{Address, AddressError, PublicKey, PublicKeyError};

use pairing::bls12_381::Bls12;
use secp256k1;
use std::cmp::{Eq, PartialEq};
use std::marker::PhantomData;
use std::str::FromStr;
use std::{fmt, fmt::Display};
use zcash_primitives::{keys::FullViewingKey, JUBJUB};

use sapling_crypto::jubjub::JubjubBls12;

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
pub struct SproutViewingKey {}

#[derive(Debug, Clone)]
pub struct SaplingViewingKey(pub(super) FullViewingKey<Bls12>);

impl PartialEq for SaplingViewingKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.vk.ak == other.0.vk.ak && self.0.vk.nk == other.0.vk.nk && self.0.ovk == other.0.ovk
    }
}

impl Eq for SaplingViewingKey {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewingKey {
    /// P2PKH transparent viewing key
    P2PKH(P2PKHViewingKey),
    /// P2SH transparent viewing key
    P2SH(P2SHViewingKey),
    /// Sprout shielded viewing key
    Sprout(SproutViewingKey),
    /// Sapling shielded viewing key
    Sapling(SaplingViewingKey),
}

///Represents a Zcash public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZcashPublicKey<N: ZcashNetwork>(ViewingKey, PhantomData<N>);

impl<N: ZcashNetwork> PublicKey for ZcashPublicKey<N> {
    type Address = ZcashAddress<N>;
    type Format = Format;
    type PrivateKey = ZcashPrivateKey<N>;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        match &private_key.to_spending_key() {
            SpendingKey::P2PKH(spending_key) => Self(
                ViewingKey::P2PKH(P2PKHViewingKey {
                    public_key: secp256k1::PublicKey::from_secret_key(
                        &secp256k1::Secp256k1::new(),
                        &spending_key.secret_key,
                    ),
                    compressed: spending_key.compressed,
                }),
                PhantomData,
            ),
            SpendingKey::P2SH(_) => Self(ViewingKey::P2SH(P2SHViewingKey {}), PhantomData),
            SpendingKey::Sprout(_) => Self(ViewingKey::Sprout(SproutViewingKey {}), PhantomData),
            SpendingKey::Sapling(spending_key) => Self(
                ViewingKey::Sapling(SaplingViewingKey(FullViewingKey::<Bls12>::from_expanded_spending_key(
                    &spending_key.expanded_spending_key,
                    &JUBJUB,
                ))),
                PhantomData,
            ),
        }
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        ZcashAddress::<N>::from_public_key(self, format)
    }
}

impl<N: ZcashNetwork> ZcashPublicKey<N> {
    /// Returns a Zcash public key given a viewing key.
    pub fn from_viewing_key(viewing_key: ViewingKey) -> Self {
        Self(viewing_key, PhantomData)
    }

    /// Returns the viewing key of the Zcash public key.
    pub fn to_viewing_key(&self) -> ViewingKey {
        self.0.clone()
    }
}

impl<N: ZcashNetwork> FromStr for ZcashPublicKey<N> {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        match public_key.len() {
            66 | 130 => Ok(Self(
                ViewingKey::P2PKH(P2PKHViewingKey {
                    public_key: secp256k1::PublicKey::from_str(public_key)?,
                    compressed: public_key.len() == 66,
                }),
                PhantomData,
            )),
            192 => {
                let data = hex::decode(public_key)?;
                let fvk = FullViewingKey::read(&data[..], &JubjubBls12::new())?;
                Ok(Self(ViewingKey::Sapling(SaplingViewingKey(fvk)), PhantomData))
            }
            _ => Err(PublicKeyError::InvalidCharacterLength(public_key.len())),
        }
    }
}

impl<N: ZcashNetwork> Display for ZcashPublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            ViewingKey::P2PKH(p2pkh) => {
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
            ViewingKey::Sapling(sapling) => {
                for s in &sapling.0.to_bytes()[..] {
                    write!(f, "{:02x}", s)?;
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

    mod sapling_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "bb69cdb5e70e2bbd24f771cd15a18ad58d3ab9e1aa3cab186b9b65d17f7aadef",
                "d21167e8ae8ccbcd34f96ec58bdf798ca7994217d03812100ea9e5cd4e1596ce3a3cf2b6c632c45d9da3b0c044d82655969f71652507eebf25e504486b7fb8e4afc9f1e8cf6b8eae18b786ec79d218d0a1cff90b43273ea162da99a9d2e21dff",
                "zs1dq9dlh6u6hna0u96aqtynxt3acddtgkgdx4re65500nmc2aze0my65ky36vaqvj4hkc9ut66eyf"
            ),
            (
                "7be697adb66f36d37b12dcdbdea38fbaec8340402de43bfe016f3c10b6a7220e",
                "1ac13265a8948db61e1614c50a71bc0af2fee7e9814d041b4c8a6a6a5bcfc9cc64b5eb4632e433a0eccc9db485121625345950693c90244e656faf2b1a356f0eb04548d7772c9be13301a71c497afc8d46f805ebce5066371a5548db109611e3",
                "zs1vvdj0st065ngdruymdcdy63duuavjeww3a2yyeu5tsqj2azhvwgkcaw9ngggfas6h4z4whnkpwz"
            ),
            (
                "0c9f5d70eaac46862150ae3f2a4eecc68753a72567eb66210df8e18a91425adf",
                "bb2d4d7e05b1afb686a7e4d7d8e82a592f25b26caa78a06e939e0ef835c6100c738d89a62c2acd969ef1c68d67d9d365b277145cc60a8e95e11315e192b22c29f612476ea95aa2d4b7df5b881c363829b39ccaa6318c6df3bd2ba6274a15fea0",
                "zs1akf8swew32rr4n63qedewhp2yz3wcjeazp6efs82lgealmux0h30ayju440rqyuscdr3wd5yuap"
            ),
            (
                "fc1edae9146d5c7f9398871ac09097fea6c1593e8c7b6f3384af36ff9cc3b2ee",
                "d610ec21ba084c1b4f42e9c38eefce1dfbf5c0843a549d08b5119007745b171db468b58307cd2c7e54ede334c4e98593e21776043e8956740b102513c03cb023301a9133ee59b826143304b041d8e1f2f1f91d3625ad7dac9e4c88e630a76d8d",
                "zs14q3vapgrd6wfs9pr7hfy37y9djm3gnq09ztxsqs2x2vzv0lck978843q8r2ysejgwp9mcx7ws48"
            ),
            (
                "6038f5e45498c92edd5e6a2588bcce7bcbac604e4e825ee7015d11f33d1e9673",
                "9847a15f3393ad8921f2b282e3033d48adb2eae9455f1e6b77038be913e04c51967b6db4f726fc21c57cf73d3c1fac7d044bc8ea2c5a75334f4641d18f2d0c1335c884a4853f740e93e55d7b9a7b82e7d8c6d17b2305282143359807f2d690d1",
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
                "49110debf1fac0086a2fabd60aab413d0281732b6e51a03dd6ec4f334469ef9f",
                "35d5cf61a3d8cf3078112693c1839a14307179008ea5f0902810d03e4a05d8bd194129f2b82ded4a973ad24aa3e4d8e49a10e039f5060616981511d6a888ca8eca66a812697612fc31fa4e0928ac144a3938d5793beda10f7513e15a6f95ad80",
                "ztestsapling1jzzt7gjscav7lmdpemknv0v8rmmdzpcaqrx95azrgaky94drrvf0fg4wlnlkaclqj3r3s23g2sf"
            ),
            (
                "4e9d5d14d776a93e8aa1dd7e69eda7cefd9651ad140443ca11553e379b2ae90b",
                "b8f5a0b850db6424b704e0eda9d01ef472fc58dd1519cb60a97d9240641e105e8856e062da9c729bb3580b64c5d933190af86066e518922e7967255746c024ea4bc12f2e92f93f4f853161bf774fe4d9c32581020c9cc52ee42216c8e575d4bb",
                "ztestsapling19epsvtxnzf59pr993fq4g0gu0fmrn2jl2z9jm2lgj3220c7r9shyvcpe25ul7wxvzk60z82zyf7"
            ),
            (
                "8544e9cfc6423e22bca5b62bf56649fd3716b6cc092391ecba78fb017d5feda1",
                "75b6233bd29155a361ec2a98552f5c1ddded2fd47af880d78a3f26b4ce8cc2d262008e3d2904bfeb61abdb70432860fbe6557a406c1ae72a4a204fe934985116cdf80f5b52fbc7d22c2dd630939b7641cec76b2e4f8ef6dc53276ea4b3efc1a9",
                "ztestsapling18ur694qcm6w657u9xt8aekutn98gyvpzwzjgjz99594x775ppeze5vwnp2ndw0u205vkuh2tqcu"
            ),
            (
                "6d21907f6ad14d2823625036e0951a3c566d4df7b101dfb2899107d02e9bd8bd",
                "e35af2ffa9c77482e11d998d087492e9f80672558253ef30ddb6d712d51a4aacc58455349ccd5be0de5a9584cfe63a5be7e86eb9f20f8efb3fb1ef84d8fc6625aa38f308de656736fb6b02929d695bb904108d5b680952ce774e938b3c50418b",
                "ztestsapling1hkyeldalqna6kxzkkpc3gl4yvtd842sld4kkx7mhtm4srhndnqm347q7x672t05j245skqsctvs"
            ),
            (
                "d800f2b919cb06f7396a9e253c77f65e1cb5f972372cac196ec6546e09355bfe",
                "1ba76bdbb4036d8564562e6664af996c53eebd5fd0209894d9100d6caf3fd149bb2550161ca124c672d7d5d2d7fd9fbbda1423e49585f22d269f59898c58e5bdea43b13df61ecd6cd23e6151a873e575db9b54a43e17cd5b12a406f6e9db6073",
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

use crate::address::{ZcashAddress, Format};
use crate::network::Network;
use crate::private_key::ZcashPrivateKey;
use wagu_model::{Address, PublicKey};

use secp256k1;
use std::{fmt, fmt::Display};
use std::str::FromStr;

///Represents a Zcash public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashPublicKey {
    /// The ECDSA public key
    pub public_key: secp256k1::PublicKey,
    /// If true, the public key is serialized in compressed form
    pub compressed: bool,
}

impl PublicKey for ZcashPublicKey {
    type Address = ZcashAddress;
    type Format = Format;
    type Network = Network;
    type PrivateKey = ZcashPrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key.secret_key);
        Self { public_key, compressed: private_key.compressed }
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format, network: &Self::Network) -> Self::Address {
        ZcashAddress::from_public_key(self, format, network)
    }
}

impl FromStr for ZcashPublicKey {
    type Err = &'static str;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            public_key: match secp256k1::PublicKey::from_str(public_key) {
                Ok(key) => key,
                _ => return Err("invalid public key")
            },
            compressed: public_key.len() == 66
        })
    }
}

impl Display for ZcashPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.compressed {
            for s in &self.public_key.serialize()[..] {
                write!(f, "{:02x}", s)?;
            }
        } else {
            for s in &self.public_key.serialize_uncompressed()[..] {
                write!(f, "{:02x}", s)?;
            }
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_from_private_key(expected_public_key: &ZcashPublicKey, private_key: &ZcashPrivateKey) {
        let public_key = ZcashPublicKey::from_private_key(private_key);
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address(
        expected_address: &ZcashAddress,
        expected_format: &Format,
        expected_network: &Network,
        public_key: &ZcashPublicKey
    ) {
        let address = public_key.to_address(expected_format, expected_network);
        assert_eq!(*expected_address, address);
    }

    fn test_from_str(
        expected_public_key: &str,
        expected_address: &str,
        expected_compressed: bool,
        expected_format: &Format,
        expected_network: &Network
    ) {
        let public_key = ZcashPublicKey::from_str(expected_public_key).unwrap();
        let address = public_key.to_address(expected_format, expected_network);
        assert_eq!(expected_public_key, public_key.to_string());
        assert_eq!(expected_compressed, public_key.compressed);
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
    }

    fn test_to_str(expected_public_key: &str, public_key: &ZcashPublicKey) {
        assert_eq!(expected_public_key, public_key.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "L3a3yRcYATnZQt7ams14Pe5KCyRzrrCSejDyeQzHXGntToffVH4g",
                "0310d63f8c2f0a6efd13ce8a77776de26eba1816f73aa73e73a4da3f2368fcc949",
                "t1JwBjJWgNQVqWxGha2RsPZMhVGgfRg2pod"
            ),
            (
                "Kx7f3xE2TmhczSkFUxxSajE2vuuLrrqinAbTZBxqxHj6XGbhoyrQ",
                "02f4bf56c9c8389b04752236a4f2419367e3a4e36fe80da6162a0b530ca91262b0",
                "t1VnZLVwvaUsnYt34XJHNTu24wn3kD8RwsE"
            ),
            (
                "L46n9WGR671oANndbkxBBz9orQ36TQu98zeRJmp41tqk3HM6UpJk",
                "031347c183c608c629e8bc0ad76718cc9f2a1ee9e53d45862a1b9c8fad25f8ab5b",
                "t1N8HuTxFm9qS7yQCi3TsMGCQ8kPPTx5Me7"
            ),
            (
                "L2AMjT43hZQGATgtkakVMMMEguoJLwDAcZJVg1zsqjWeWaC4cTVd",
                "03a0d8ab54a080f6e085777c2f5432b22b3543ad421aecc3f2136bcd2e1e2a59e4",
                "t1PUKYyoqPZw43CHqjquU9PZE1GEvmHNbPa"
            ),
            (
                "L53GxzD5rVaX6jY5ig1qNBqur5WyAeFn8sCo9VwU4J717ewDbgc6",
                "020ceda15424ec7159f7ac5f6ad2654c93ab4cae7f9419de7aae39967f97907fd7",
                "t1TqidZPmPSJsr1wcMuYwDDaa7D9ow5sWMx"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let public_key = ZcashPublicKey::from_str(&public_key).unwrap();
                test_to_address(&address, &Format::P2PKH, &Network::Mainnet, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str(
                    expected_public_key,
                    expected_address,
                    true,
                    &Format::P2PKH,
                    &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

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
                let public_key = ZcashPublicKey::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let public_key = ZcashPublicKey::from_str(&public_key).unwrap();
                test_to_address(&address, &Format::P2PKH, &Network::Mainnet, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str(
                    expected_public_key,
                    expected_address,
                    false,
                    &Format::P2PKH,
                    &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "cNG7sM13VvGrhKgepLeEiiQAERXpGB6j5NuRwhh6sLh2skMTQf7M",
                "02d327c40e543a08c17cda94d0b9660520bd075151280e487294e94eced3a283df",
                "tmWT3bvWCHQkAXXucPjWHqLs9EyWUDdzSuN"
            ),
            (
                "cQXFXQHBzCuPbKYdeKERGeMrh8TJAsos7TLYDamQLXJiXY9sUkY6",
                "038a2754d1b25a7d0cb3518ea92ca07de0fc21a56d920be6ca10857893c48989fb",
                "tmAs578aq6jaXqmnXRrhWpjJsySFf7eXb5J"
            ),
            (
                "cQNALaabLLxMzdBkbCZvcTJtyvQ5zg4UhhskMk5R8Wu1ymSXCLsX",
                "0309341fa999f0f2951eb9867f84b55781904fe2228b8ffc8dc1a8a47e1c357957",
                "tmD8R6k2mTfTwGG24w5SBeAwQnqKGFx3cSg"
            ),
            (
                "cS6qPDRjncjCAe95SGKH81491NGkwzWqhAsGTEzkgVNC6ZdBpB4M",
                "024e12c05184403e0243a1563b9ebaeda7b529bf1306abe55827d363697be936a4",
                "tmPNWe7d4Hvkh4TEZ6Xd1ZQBje7VNQQ2Anb"
            ),
            (
                "cRRjNZuyYu8aiqVLRLvj7PqTWKLELK2N257AgSvmPzMjfJ44oWtb",
                "03d08c6748dcad37dbcad05d4cde25234107785a1c19b6edda8bfc199c91877d7d",
                "tmRdRE5JAX6KX3c11GVgqc5R6JBRtfbuk8i"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let public_key = ZcashPublicKey::from_str(&public_key).unwrap();
                test_to_address(&address, &Format::P2PKH, &Network::Testnet, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str(
                    expected_public_key,
                    expected_address,
                    true,
                    &Format::P2PKH,
                    &Network::Testnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

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
                let public_key = ZcashPublicKey::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let public_key = ZcashPublicKey::from_str(&public_key).unwrap();
                test_to_address(&address, &Format::P2PKH, &Network::Testnet, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str(
                    expected_public_key,
                    expected_address,
                    false,
                    &Format::P2PKH,
                    &Network::Testnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = ZcashPublicKey::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
        }
    }

    #[test]
    fn test_p2pkh_invalid() {

        // Invalid public key length

        let public_key = "0";
        assert!(ZcashPublicKey::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44";
        assert!(ZcashPublicKey::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db";
        assert!(ZcashPublicKey::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5039ed714bf521e96e3f3609b74da898e44";
        assert!(ZcashPublicKey::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5";
        assert!(ZcashPublicKey::from_str(public_key).is_err());

    }
}

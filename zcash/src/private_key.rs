use crate::address::{ZcashAddress, Format};
use crate::network::Network;
use crate::public_key::ZcashPublicKey;
use model::{Address, PrivateKey, PublicKey, crypto::checksum};

use base58::{FromBase58, ToBase58};
use rand::Rng;
use rand::rngs::OsRng;
use secp256k1::Secp256k1;
use secp256k1;
use std::{fmt, fmt::Display};
use std::str::FromStr;

/// Represents a Zcash Private Key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZcashPrivateKey {
    /// The ECDSA private key
    pub secret_key: secp256k1::SecretKey,
    /// The Wallet Import Format (WIF) string encoding
    pub wif: String,
    /// The network of the private key
    pub network: Network,
    /// If true, the private key is serialized in compressed form
    pub compressed: bool,
}

impl PrivateKey for ZcashPrivateKey {
    type Address = ZcashAddress;
    type Format = Format;
    type Network = Network;
    type PublicKey = ZcashPublicKey;

    /// Returns a randomly-generated compressed Zcash private key.
     fn new(network: &Network) -> Self {
        Self::build(network, true)
    }

    /// Returns the public key of the corresponding Zcash private key.
     fn to_public_key(&self) -> Self::PublicKey {
        ZcashPublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Zcash private key.
    fn to_address(&self, format: &Self::Format) -> Self::Address {
        ZcashAddress::from_private_key(self, format)
    }
}

impl ZcashPrivateKey {
    /// Returns either a Zcash private key struct or errors.
    pub fn from_wif(wif: &str) -> Result<Self, &'static str> {
        let data = wif.from_base58().expect("Error decoding base58 wif");
        let len = data.len();
        if len != 37 && len != 38 {
            return Err("invalid wif length")
        }

        let expected = &data[len - 4..][0..4];
        let checksum = &checksum(&data[0..len - 4])[0..4];

        match *expected == *checksum {
            true => Ok(Self {
                network: Network::from_wif_prefix(data[0])?,
                wif: wif.to_string(),
                secret_key: secp256k1::SecretKey::from_slice(&Secp256k1::without_caps(), &data[1..33])
                    .expect("Error creating secret key from slice"),
                compressed: len == 38,
            }),
            false => Err("Invalid wif")
        }
    }

    /// Returns a private key given a secp256k1 secret key
    pub fn from_secret_key(secret_key: secp256k1::SecretKey, network: &Network, compressed: bool) -> Self {
        let wif = Self::secret_key_to_wif(&secret_key, network, compressed);
        Self { secret_key, wif, network: *network, compressed}
    }

    /// Returns a randomly-generated Zcash private key.
    fn build(network: &Network, compressed: bool) -> Self {
        let secret_key = Self::random_secret_key();
        let wif = Self::secret_key_to_wif(&secret_key, network, compressed);
        Self { secret_key, wif, network: *network, compressed }
    }

    /// Returns a randomly-generated a secp256k1 secret key.
    fn random_secret_key() -> secp256k1::SecretKey {
        let mut random = [0u8; 32];
        OsRng.try_fill(&mut random).expect("Error generating random bytes for private key");
        secp256k1::SecretKey::from_slice(&Secp256k1::new(), &random)
            .expect("Error creating secret key from byte slice")
    }

    /// Returns a WIF string given a secp256k1 secret key.
    fn secret_key_to_wif(secret_key: &secp256k1::SecretKey, network: &Network, compressed: bool) -> String {
        let mut wif = [0u8; 38];
        wif[0] = network.to_wif_prefix();
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
}

impl Default for ZcashPrivateKey {
    /// Returns a randomly-generated mainnet Zcash private key.
    fn default() -> Self {
        Self::new(&Network::Mainnet)
    }
}

impl FromStr for ZcashPrivateKey {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, &'static str> {
        Self::from_wif(s)
    }
}

impl Display for ZcashPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.wif)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_to_public_key(expected_public_key: &ZcashPublicKey, private_key: &ZcashPrivateKey) {
        let public_key = private_key.to_public_key();
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address(expected_address: &ZcashAddress, expected_format: &Format, private_key: &ZcashPrivateKey) {
        let address = private_key.to_address(expected_format);
        assert_eq!(*expected_address, address);
    }

    fn test_from_wif(
        expected_secret_key: &secp256k1::SecretKey,
        expected_network: &Network,
        expected_compressed: bool,
        expected_public_key: &str,
        expected_address: &str,
        expected_format: &Format,
        wif: &str
    ) {
        let private_key = ZcashPrivateKey::from_wif(wif).unwrap();
        assert_eq!(*expected_secret_key, private_key.secret_key);
        assert_eq!(wif, private_key.wif);
        assert_eq!(*expected_network, private_key.network);
        assert_eq!(expected_compressed, private_key.compressed);
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(expected_address, private_key.to_address(expected_format).to_string());
    }

    fn test_from_secret_key(
        expected_wif: &str,
        expected_network: &Network,
        expected_compressed: bool,
        expected_public_key: &str,
        expected_address: &str,
        expected_format: &Format,
        secret_key: secp256k1::SecretKey,
        network: &Network,
        compressed: bool
    ) {
        let private_key = ZcashPrivateKey::from_secret_key(secret_key, network, compressed);
        assert_eq!(secret_key, private_key.secret_key);
        assert_eq!(expected_wif, private_key.wif);
        assert_eq!(*expected_network, private_key.network);
        assert_eq!(expected_compressed, private_key.compressed);
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(expected_address, private_key.to_address(expected_format).to_string());
    }

    fn test_to_str(expected_private_key: &str, private_key: &ZcashPrivateKey) {
        assert_eq!(expected_private_key, private_key.to_string());
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
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_to_address(&address, &Format::P2PKH, &private_key);
            });
        }

        #[test]
        fn from_wif() {
            KEYPAIRS.iter().for_each(|(private_key, expected_public_key, expected_address)| {
                let expected_private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_from_wif(
                    &expected_private_key.secret_key,
                    &Network::Mainnet,
                    true,
                    expected_public_key,
                    expected_address,
                    &Format::P2PKH,
                    &private_key);
            });
        }

        #[test]
        fn from_secret_key() {
            KEYPAIRS.iter().for_each(|(expected_private_key, expected_public_key, expected_address)| {
                let private_key = ZcashPrivateKey::from_str(&expected_private_key).unwrap();
                test_from_secret_key(
                    expected_private_key,
                    &Network::Mainnet,
                    true,
                    expected_public_key,
                    expected_address,
                    &Format::P2PKH,
                    private_key.secret_key,
                    &Network::Mainnet,
                    true);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
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
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_to_address(&address, &Format::P2PKH, &private_key);
            });
        }

        #[test]
        fn from_wif() {
            KEYPAIRS.iter().for_each(|(private_key, expected_public_key, expected_address)| {
                let expected_private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_from_wif(
                    &expected_private_key.secret_key,
                    &Network::Mainnet,
                    false,
                    expected_public_key,
                    expected_address,
                    &Format::P2PKH,
                    &private_key);
            });
        }

        #[test]
        fn from_secret_key() {
            KEYPAIRS.iter().for_each(|(expected_private_key, expected_public_key, expected_address)| {
                let private_key = ZcashPrivateKey::from_str(&expected_private_key).unwrap();
                test_from_secret_key(
                    expected_private_key,
                    &Network::Mainnet,
                    false,
                    expected_public_key,
                    expected_address,
                    &Format::P2PKH,
                    private_key.secret_key,
                    &Network::Mainnet,
                    false);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
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
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_to_address(&address, &Format::P2PKH, &private_key);
            });
        }

        #[test]
        fn from_wif() {
            KEYPAIRS.iter().for_each(|(private_key, expected_public_key, expected_address)| {
                let expected_private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_from_wif(
                    &expected_private_key.secret_key,
                    &Network::Testnet,
                    true,
                    expected_public_key,
                    expected_address,
                    &Format::P2PKH,
                    &private_key);
            });
        }

        #[test]
        fn from_secret_key() {
            KEYPAIRS.iter().for_each(|(expected_private_key, expected_public_key, expected_address)| {
                let private_key = ZcashPrivateKey::from_str(&expected_private_key).unwrap();
                test_from_secret_key(
                    expected_private_key,
                    &Network::Testnet,
                    true,
                    expected_public_key,
                    expected_address,
                    &Format::P2PKH,
                    private_key.secret_key,
                    &Network::Testnet,
                    true);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
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
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = ZcashPublicKey::from_str(public_key).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = ZcashAddress::from_str(address).unwrap();
                let private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_to_address(&address, &Format::P2PKH, &private_key);
            });
        }

        #[test]
        fn from_wif() {
            KEYPAIRS.iter().for_each(|(private_key, expected_public_key, expected_address)| {
                let expected_private_key = ZcashPrivateKey::from_str(&private_key).unwrap();
                test_from_wif(
                    &expected_private_key.secret_key,
                    &Network::Testnet,
                    false,
                    expected_public_key,
                    expected_address,
                    &Format::P2PKH,
                    &private_key);
            });
        }

        #[test]
        fn from_secret_key() {
            KEYPAIRS.iter().for_each(|(expected_private_key, expected_public_key, expected_address)| {
                let private_key = ZcashPrivateKey::from_str(&expected_private_key).unwrap();
                test_from_secret_key(
                    expected_private_key,
                    &Network::Testnet,
                    false,
                    expected_public_key,
                    expected_address,
                    &Format::P2PKH,
                    private_key.secret_key,
                    &Network::Testnet,
                    false);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = ZcashPrivateKey::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }
    }

    #[test]
    fn test_p2pkh_invalid() {

        // Invalid WIF length

        let private_key = "L";
        assert!(ZcashPrivateKey::from_str(private_key).is_err());

        let private_key = "L5hax5dZaByC3kJ4aLrZgnMXGSQReq";
        assert!(ZcashPrivateKey::from_str(private_key).is_err());

        let private_key = "L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42";
        assert!(ZcashPrivateKey::from_str(private_key).is_err());

        let private_key = "L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42HL5hax5dZaByC3kJ4aLrZgnMXGSQ";
        assert!(ZcashPrivateKey::from_str(private_key).is_err());

        let private_key = "L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42HL5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42H";
        assert!(ZcashPrivateKey::from_str(private_key).is_err());

    }
}
use crate::network::Network;
use crate::private_key::ZcashPrivateKey;
use crate::public_key::{P2PKHViewingKey, SaplingViewingKey, SproutViewingKey, ViewingKey, ZcashPublicKey};
use model::{Address, crypto::{checksum, hash160}, PrivateKey};

use bech32::{Bech32, FromBase32, ToBase32};
use base58::{FromBase58, ToBase58};
use rand::Rng;
use rand::rngs::OsRng;
use sapling_crypto::primitives::Diversifier;
use serde::Serialize;
use std::fmt;
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
    Sapling(Option<[u8; 11]>)
}

impl Format {
    /// Returns the address prefix of the given network.
    pub fn to_address_prefix(&self, network: &Network) -> Vec<u8> {
        match network {
            Network::Mainnet => match self {
                Format::P2PKH => vec![0x1C, 0xB8],
                Format::P2SH => vec![0x1C, 0xBD],
                Format::Sprout => vec![0x16, 0x9A],
                Format::Sapling(_) => "zs".as_bytes().to_vec()
            },
            Network::Testnet => match self {
                Format::P2PKH => vec![0x1D, 0x25],
                Format::P2SH => vec![0x1C, 0xBA],
                Format::Sprout => vec![0x16, 0xB6],
                Format::Sapling(_) => "ztestsapling".as_bytes().to_vec()
            },
        }
    }

    /// Returns the format of the given address prefix.
    pub fn from_address_prefix(prefix: &Vec<u8>) -> Result<Self, &'static str> {
        if prefix.len() < 2 {
            return Err("invalid prefix length")
        }

        match prefix[1] {
            0xB8 | 0x25 => Ok(Format::P2PKH),
            0xBD | 0xBA => Ok(Format::P2SH),
            0x9A | 0xB6 => Ok(Format::Sprout),
            0x73 | 0x74 => Ok(Format::Sapling(None)),
            _ => return Err("invalid address prefix")
        }
    }
}

/// Represents a Zcash address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashAddress {
    /// The Zcash address
    pub address: String,
    /// The format of the address
    pub format: Format,
    /// The network on which this address is usable
    pub network: Network,
}

impl Address for ZcashAddress {
    type Format = Format;
    type Network = Network;
    type PrivateKey = ZcashPrivateKey;
    type PublicKey = ZcashPublicKey;

    /// Returns the address corresponding to the given Zcash private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Self {
        match private_key.to_public_key().0 {
            ViewingKey::P2PKH(public_key) => Self::p2pkh(&public_key, &private_key.network()),
            ViewingKey::P2SH(public_key) => Self::p2sh( &private_key.network()),
            ViewingKey::Sprout(public_key) => Self::sprout(&public_key, &private_key.network()),
            ViewingKey::Sapling(public_key) => Self::sapling(&public_key, format, &private_key.network())
        }
    }

    /// Returns the address corresponding to the given Zcash public key.
    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
        network: &Self::Network
    ) -> Self {
        match &public_key.0 {
            ViewingKey::P2PKH(public_key) => Self::p2pkh(&public_key, network),
            ViewingKey::P2SH(public_key) => Self::p2sh(network),
            ViewingKey::Sprout(public_key) => Self::sprout(&public_key, network),
            ViewingKey::Sapling(public_key) => Self::sapling(&public_key, format, network)
        }
    }
}

impl ZcashAddress {
    /// Returns a transparent address from a given Zcash public key.
    pub fn p2pkh(public_key: &P2PKHViewingKey, network: &Network) -> Self {

        let mut address = [0u8; 26];
        address[0..2].copy_from_slice(&Format::P2PKH.to_address_prefix(network));
        address[2..22].copy_from_slice(&hash160(&match public_key.compressed {
            true => public_key.public_key.serialize().to_vec(),
            false => public_key.public_key.serialize_uncompressed().to_vec()
        }));

        let sum = &checksum(&address[0..22])[0..4];
        address[22..26].copy_from_slice(sum);

        Self { address: address.to_base58(), format: Format::P2PKH, network: *network }
    }

    /// Returns a P2SH address.
    // TODO (howardwu): implement address scheme
    pub fn p2sh(_network: &Network) -> Self {
        unimplemented!("p2sh addresses are unimplemented");
    }

    /// Returns a shielded address from a given Zcash public key.
    // TODO (howardwu): implement address scheme
    pub fn sprout(_public_key: &SproutViewingKey, _network: &Network) -> Self {
        unimplemented!("sprout addresses are unimplemented");
    }

    /// Returns a shielded address from a given Zcash public key.
    pub fn sapling(public_key: &SaplingViewingKey, format: &Format, network: &Network) -> Self {
        let diversifier = match format {
            Format::Sapling(diversifier) => match diversifier {
                Some(diversifier) => match public_key.0.vk.into_payment_address(Diversifier(*diversifier), &JUBJUB) {
                    Some(_) => Some(diversifier),
                    None => None
                },
                None => None
            },
            _ => None
        };

        let diversifier = match diversifier {
            Some(diversifier) => *diversifier,
            None => {
                let mut diversifier = [0u8; 11];
                loop {
                    OsRng.try_fill(&mut diversifier).expect("error generating random bytes for diversifier");
                    if let Some(address) = public_key.0.vk.into_payment_address(Diversifier(diversifier), &JUBJUB) {
                        break;
                    }
                }
                diversifier
            }
        };

        let mut checked_data = vec![0; 43];
        checked_data.get_mut(..11).unwrap().copy_from_slice(&diversifier);

        let address = public_key.0.vk.into_payment_address(Diversifier(diversifier), &JUBJUB).expect("invalid payment address");
        address.pk_d.write(checked_data.get_mut(11..).unwrap()).expect("invalid write");

        let prefix = network.to_address_prefix(&Format::Sapling(Some(diversifier)));

        return Self {
            address: Bech32::new(
                String::from(str::from_utf8(&prefix).expect("invalid prefix")),
                checked_data.to_base32()).expect("bech32 failed").to_string(),
            format: Format::Sapling(Some(diversifier)),
            network: *network
        }
    }

    pub fn get_diversifier(address: &str) -> [u8; 11] {
        let address = Bech32::from_str(address).expect("invalid bech32 address");
        let buffer: Vec<u8> = FromBase32::from_base32(address.data()).expect("invalid base32 encoding");
        let mut diversifier = [0u8; 11];
        diversifier.copy_from_slice(&buffer[0..11]);
        diversifier
    }
}

impl FromStr for ZcashAddress {
    type Err = &'static str;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() < 2 {
            return Err("invalid address length");
        }

        // Transparent
        if &address[0..=0] == "t" && address.len() < 40 {
            match &address[1..=1] {
                "1" | "m" => {
                    let data = address.from_base58().expect("invalid base58 format");
                    if data.len() != 26 {
                        return Err("invalid byte length");
                    }

                    let format = Format::from_address_prefix(&data[0..2].to_vec())?;
                    let network = Network::from_address_prefix(&data[0..2].to_vec())?;

                    return Ok(Self { address: address.into(), format, network });
                },
                "3" | "2" => {
                    unimplemented!("");
                },
                _ => return Err("invalid address prefix")
            }
        }

        // Shielded
        if &address[0..=0] == "z" && address.len() > 77 {
            if &address[0..12] == "ztestsapling" && address.len() > 87 {

                let format = Format::Sapling(Some(Self::get_diversifier(address)));
                let network = Network::Testnet;
                return Ok(Self { address: address.into(), format, network });

            } else if &address[0..2] == "zs" && address.len() > 77 {

                let format = Format::Sapling(Some(Self::get_diversifier(address)));
                let network = Network::Mainnet;
                return Ok(Self { address: address.into(), format, network });

            } else if &address[0..2] == "zt" && address.len() == 95 {

                let format = Format::Sprout;
                let network = Network::Testnet;
                return Ok(Self { address: address.into(), format, network });

            } else if &address[0..2] == "zc" && address.len() == 95 {

                let format = Format::Sprout;
                let network = Network::Mainnet;
                return Ok(Self { address: address.into(), format, network });

            }
        }

        Err("invalid address string")
    }
}

impl fmt::Display for ZcashAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::public_key::PublicKey;

    fn test_from_private_key(
        expected_address: &str,
        private_key: &ZcashPrivateKey,
        format: &Format,
    ) {
        let address = ZcashAddress::from_private_key(private_key, format);
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key(
        expected_address: &str,
        public_key: &ZcashPublicKey,
        format: &Format,
        network: &Network,
    ) {
        let address = ZcashAddress::from_public_key(public_key, format, network);
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str(expected_address: &str, expected_format: &Format, expected_network: &Network) {
        let address = ZcashAddress::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
        assert_eq!(*expected_network, address.network);
    }

    fn test_to_str(expected_address: &str, address: &ZcashAddress) {
        assert_eq!(expected_address, address.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "KxYzZuBPkE3rnEEGCdsB6dCzxN1D4xoY5ogKoxbdUdkxbRzvgbij",
                "t1MoMR1XdnPqLBWf5XkchWTkGNrveYLCaiM"
            ),
            (
                "KyuC6qNxMiuPEF4wp6eLsJuczLKqHsdsdSx5c3a1boY81mpahuR6",
                "t1cnUnLfXZsb7gM7h9zD6QXm1wEDi4NxvTi"
            ),
            (
                "KxNLHESzCRfzTfF9KGsF68QtV9fT9qFRAH5UKpVUdMvc4TTcBmhJ",
                "t1VenYPx8HCiq6YFbuh1HbLGwtDZxQ5hQCr"
            ),
            (
                "L5XgV3xUnqcqJyJm3JZmtZyj5i8FmUbuj9LCz9n3FA87Ertn2Qod",
                "t1U9A7fh864FCzePbrXeUdjvuMfuCYKijbr"
            ),
            (
                "L17dC6ZcGfKu84FGastka34sB8yV9fzgbKJaafVWi4zKs6ETnF2x",
                "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Mainnet).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Mainnet).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH, &Network::Mainnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2PKH, &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "5HwduFgmNrhcgXpD7TH2ZbqBzfET3FzRLwapJdZYUNyxPz6MYQU",
                "t1gxf6ykX23Ha3Bf1bKhjJzdxtCPratotJK"
            ),
            (
                "5KFcAbDaap4ZqF1pCTq6rKWU6bUZg3bnqHJYaCEh6NUu8aVTszm",
                "t1QnYYpiVpmwHPtrRSJqypnDxG77284NUtj"
            ),
            (
                "5KXotG2j5THVbdf2Uf87HPZFRNaVqZYrrBVnZzczyDVza39q94f",
                "t1XEXEt3KeEYzycPTzn3invLivktYifWuXJ"
            ),
            (
                "5KPN7LeX6uzBpTYdC28xjgHkN5XbCKZVJiu9QquSCEFJcD7ndnv",
                "t1VxdN6a4T6RiSwgkNURkHhjLuoThvZWaHC"
            ),
            (
                "5JewwWXmgcdk9P762F3Pdr8RBcWfWVAAotq9mjSNBcEvZsQBJ32",
                "t1XraTEGoX5QjnhAqDs9F8AqvDEh4zohhUQ"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Mainnet).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Mainnet).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH, &Network::Mainnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2PKH, &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "cPFtCjL9EXtgZQJSD13NMn1p3mhoXXHSqF9kXEX97XNPsz1b97ti",
                "tmW3honY9Uz7WhSJPwRD5UPHY942RpoYcPM"
            ),
            (
                "cRbB17stVTkcZ38o8xx6qRQod6Ucof55YgLa86yL8jtwVr1YfgcB",
                "tmP5MuXAzJEPS3GvjBeAiZUmrzYxuC6dUHv"
            ),
            (
                "cMm7vvjXYJGqLCTc1FcQmmteXYGNduUAVS25WCvyqQvWNTENabQF",
                "tmPeoJrhUAhcb4nXS3mCqdSBJuGTcX6s2sm"
            ),
            (
                "cVrMaRzQ4YkbQSJr595Lr9aem2UHomoFikSQNPKqHoZUdaicJBa6",
                "tmNEZVphFWo5vh5xfb1k5STFFMZ6yijzfKC"
            ),
            (
                "cNLN6kBQJ68w1idp9TiUDbiLPnZ9vm9THDXE6nGBER1g7Pv4GycX",
                "tmL1yemb1GvbS4SUzYQTirdGm7WSDREQgow"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Testnet).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Testnet).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH, &Network::Testnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2PKH, &Network::Testnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "91fek9Xs6SkDx9mm89hDNM84Y49yM446xKmdQDsLJ4uzUXX2jLg",
                "tmYkTUt1hBUcHyKtGpXYRM3tVrnL32fWDhi"
            ),
            (
                "934pAaCKAS9vb1GmiSc3tfmVbrvREF1VBo19YdEXGWEwZUee4pP",
                "tmHe2je7jqn9a7k4wpjidTCZTmFcKKUPgFu"
            ),
            (
                "91eKu9FmVPqPZTLMBwyGZygwtsFzxj49p3tF7DWGkLETUsWP7gv",
                "tmQWZNqKkn2JUJUa4DKZpzFZyN3tTLqZtMy"
            ),
            (
                "923PCzFXfoZ9sXrkBb4e1m8UzvWXATPY4uaxvLPGofCPM4AtS11",
                "tmJsXk5QzyvXCkNApr5PG6DXeHUfHbQWJsV"
            ),
            (
                "93UmH7crxTbPxq8mdJ9Vmzvk1nGEwVh4LDbg9iF7pJ2sezShhRX",
                "tmDM9R3iW5AGzmUWAPnMxCVkZYR7LLKbcnX"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Testnet).unwrap();
                test_from_private_key(address, &private_key, &Format::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Testnet).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::P2PKH, &Network::Testnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::P2PKH, &Network::Testnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod sapling_mainnet {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "bb69cdb5e70e2bbd24f771cd15a18ad58d3ab9e1aa3cab186b9b65d17f7aadef",
                "zs1dq9dlh6u6hna0u96aqtynxt3acddtgkgdx4re65500nmc2aze0my65ky36vaqvj4hkc9ut66eyf"
            ),
            (
                "7be697adb66f36d37b12dcdbdea38fbaec8340402de43bfe016f3c10b6a7220e",
                "zs1vvdj0st065ngdruymdcdy63duuavjeww3a2yyeu5tsqj2azhvwgkcaw9ngggfas6h4z4whnkpwz"
            ),
            (
                "0c9f5d70eaac46862150ae3f2a4eecc68753a72567eb66210df8e18a91425adf",
                "zs1akf8swew32rr4n63qedewhp2yz3wcjeazp6efs82lgealmux0h30ayju440rqyuscdr3wd5yuap"
            ),
            (
                "fc1edae9146d5c7f9398871ac09097fea6c1593e8c7b6f3384af36ff9cc3b2ee",
                "zs14q3vapgrd6wfs9pr7hfy37y9djm3gnq09ztxsqs2x2vzv0lck978843q8r2ysejgwp9mcx7ws48"
            ),
            (
                "6038f5e45498c92edd5e6a2588bcce7bcbac604e4e825ee7015d11f33d1e9673",
                "zs1rzjhudlm99h5fyrh7dfsvkfg9l5z587w97pm3ce9hpwfxpgck6p55lwu5mcapz7g3r40y597n2c"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::Sapling(None), &Network::Mainnet).unwrap();
                test_from_private_key(address, &private_key, &Format::Sapling(Some(ZcashAddress::get_diversifier(address))));
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::Sapling(None), &Network::Mainnet).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::Sapling(Some(ZcashAddress::get_diversifier(address))), &Network::Mainnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::Sapling(Some(ZcashAddress::get_diversifier(address))), &Network::Mainnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod sapling_testnet {
        use super::*;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "49110debf1fac0086a2fabd60aab413d0281732b6e51a03dd6ec4f334469ef9f",
                "ztestsapling1jzzt7gjscav7lmdpemknv0v8rmmdzpcaqrx95azrgaky94drrvf0fg4wlnlkaclqj3r3s23g2sf"
            ),
            (
                "4e9d5d14d776a93e8aa1dd7e69eda7cefd9651ad140443ca11553e379b2ae90b",
                "ztestsapling19epsvtxnzf59pr993fq4g0gu0fmrn2jl2z9jm2lgj3220c7r9shyvcpe25ul7wxvzk60z82zyf7"
            ),
            (
                "8544e9cfc6423e22bca5b62bf56649fd3716b6cc092391ecba78fb017d5feda1",
                "ztestsapling18ur694qcm6w657u9xt8aekutn98gyvpzwzjgjz99594x775ppeze5vwnp2ndw0u205vkuh2tqcu"
            ),
            (
                "6d21907f6ad14d2823625036e0951a3c566d4df7b101dfb2899107d02e9bd8bd",
                "ztestsapling1hkyeldalqna6kxzkkpc3gl4yvtd842sld4kkx7mhtm4srhndnqm347q7x672t05j245skqsctvs"
            ),
            (
                "d800f2b919cb06f7396a9e253c77f65e1cb5f972372cac196ec6546e09355bfe",
                "ztestsapling12n4jm24lflgmjk4crm0322p0gpmww98v5cqyurphq6tr4r4q9kxyz2f3tp9x92mm8kruwwg2u5w"
            )
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::Sapling(None), &Network::Testnet).unwrap();
                test_from_private_key(address, &private_key, &Format::Sapling(Some(ZcashAddress::get_diversifier(address))));
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = ZcashPrivateKey::from(private_key, &Format::Sapling(None), &Network::Testnet).unwrap();
                let public_key = ZcashPublicKey::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &Format::Sapling(Some(ZcashAddress::get_diversifier(address))), &Network::Testnet);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str(address, &Format::Sapling(Some(ZcashAddress::get_diversifier(address))), &Network::Testnet);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = ZcashAddress::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    #[test]
    fn test_p2pkh_invalid() {

        // Mismatched keypair

        let private_key = "KxYzZuBPkE3rnEEGCdsB6dCzxN1D4xoY5ogKoxbdUdkxbRzvgbij";
        let expected_address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt";

        let private_key = ZcashPrivateKey::from(private_key, &Format::P2PKH, &Network::Mainnet).unwrap();
        let address = ZcashAddress::from_private_key(&private_key, &Format::P2PKH);
        assert_ne!(expected_address, address.to_string());

        let public_key = ZcashPublicKey::from_private_key(&private_key);
        let address = ZcashAddress::from_public_key(&public_key, &Format::P2PKH, &Network::Mainnet);
        assert_ne!(expected_address, address.to_string());

        // Invalid address length

        let address = "t";
        assert!(ZcashAddress::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3";
        assert!(ZcashAddress::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZ";
        assert!(ZcashAddress::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZtt1J8w8EMM1Rs26zJFu3";
        assert!(ZcashAddress::from_str(address).is_err());

        let address = "t1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZtt1J8w8EMM1Rs26zJFu3Deo6ougWhNhPXUZt";
        assert!(ZcashAddress::from_str(address).is_err());

    }
}

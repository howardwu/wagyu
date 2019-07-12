use model::crypto::{checksum, hash160};
use crate::private_key::EthereumPrivateKey;
use crate::extended_public_key::EthereumExtendedPublicKey;

use base58::{FromBase58, ToBase58};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Sha512;


use std::{fmt, fmt::Display};
use std::io::Cursor;
use std::ops::AddAssign;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Ethereum Extended Private Key
#[derive(Debug, Clone)]
pub struct EthereumExtendedPrivateKey {
    /// The EthereumPrivateKey
    pub private_key: EthereumPrivateKey,

    /// The chain code corresponding to this extended private key.
    pub chain_code: [u8; 32],

    /// 0x00 for master nodes, 0x01 for level-1 derived keys, ....
    pub depth: u8,

    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    pub parent_fingerprint: [u8; 4],

    /// This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    pub child_number: u32,
}

impl EthereumExtendedPrivateKey {
    /// Generates new extended private key
    pub fn new(seed: &[u8]) -> Self {
        EthereumExtendedPrivateKey::generate_master(seed)
    }

    /// Generates new master extended private key
    fn generate_master(seed: &[u8]) -> Self {
        let mut mac = HmacSha512::new_varkey(b"Bitcoin seed").expect("Error generating hmac");
        mac.input(seed);
        let result = mac.result().code();

        let (private_key, chain_code) = EthereumExtendedPrivateKey::derive_private_key_and_chain_code(&result);
        Self {
            private_key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0x00000000,
        }
    }

    /// Generates extended private key corresponding to derivation path from the current extended private key
    pub fn derivation_path(&self, path: &str) -> Self {
        let mut path_vec: Vec<&str> = path.split("/").collect();

        if path_vec[0] != "m" {
            panic!("Invalid derivation path")
        }

        if path_vec.len() == 1 {
            return self.clone();
        }

        let mut xpriv = self.clone();
        for (_, child_str) in path_vec[1..].iter_mut().enumerate() {
            let mut child_num = 0u32;

            // add 2^31 for hardened paths
            if child_str.contains("'") {
                let child_num_trimmed: u32 = child_str.trim_end_matches("'").parse().expect("Error parsing hardened child num");

                child_num.add_assign(child_num_trimmed);
                child_num.add_assign(2u32.pow(31));
            } else {
                let child_num_u32: u32 = child_str.parse().expect("Error parsing normal child num");
                child_num.add_assign(child_num_u32);
            }
            xpriv = xpriv.ckd_priv(child_num);
        }

        xpriv
    }

    /// Generates the child extended private key at child_number from the current extended private key
    pub fn ckd_priv(&self, child_number: u32) -> Self {
        let mut mac = HmacSha512::new_varkey(
            &self.chain_code).expect("error generating hmac from chain code");
        let public_key_serialized = &PublicKey::from_secret_key(
            &Secp256k1::new(), &self.private_key.secret_key).serialize()[..];

        // Check whether i ≥ 2^31 (whether the child is a hardened key).
        // If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)). (Note: The 0x00 pads the private key to make it 33 bytes long.)
        // If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
        if child_number >= 2_u32.pow(31) {
            let mut private_key_bytes = [0u8; 33];
            private_key_bytes[1..33].copy_from_slice(&self.private_key.secret_key[..]);
            mac.input(&private_key_bytes[..]);
        } else {
            mac.input(public_key_serialized);
        }

        let mut child_num_big_endian = [0u8; 4];
        BigEndian::write_u32(&mut child_num_big_endian, child_number);
        mac.input(&child_num_big_endian);

        let result = mac.result().code();

        let (mut private_key, chain_code) = EthereumExtendedPrivateKey::derive_private_key_and_chain_code(&result);
        private_key.secret_key.add_assign(&Secp256k1::new(), &self.private_key.secret_key).expect("error add assign");

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

        Self {
            private_key,
            chain_code,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,

        }
    }

    /// Generates the extended public key associated with the current extended private key
    pub fn to_xpub(&self) -> EthereumExtendedPublicKey {
        EthereumExtendedPublicKey::from_private(&self)
    }

    /// Generates extended private key from Secp256k1 secret key and chain code
    pub fn derive_private_key_and_chain_code(result: &[u8]) -> (EthereumPrivateKey, [u8; 32]) {
        let private_key = EthereumPrivateKey::from_secret_key(
            SecretKey::from_slice(&Secp256k1::without_caps(), &result[0..32]).expect("error generating secret key"));

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);

        return (private_key, chain_code);
    }
}

impl Default for EthereumExtendedPrivateKey {
    /// Returns a randomly-generated mainnet Ethereum private key.
    fn default() -> Self {
        let mut random = [0u8; 32];
        OsRng.try_fill(&mut random).expect("Error generating random bytes for private key");
        Self::new(&random)
    }
}

impl FromStr for EthereumExtendedPrivateKey {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, &'static str> {
        let data = s.from_base58().expect("Error decoding base58 extended private key string");
        if data.len() != 82 {
            return Err("Invalid extended private key string length");
        }

        // ethereum xkeys are mainnet only
        if &data[0..4] != [0x04u8, 0x88, 0xAD, 0xE4] {
            return Err("Invalid network version");
        };

        let depth = data[4] as u8;

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_number: u32 = Cursor::new(&data[9..13]).read_u32::<BigEndian>().unwrap();

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let private_key = EthereumPrivateKey::from_secret_key(
            SecretKey::from_slice(&Secp256k1::new(), &data[46..78]).expect("Error decoding secret key string"));

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];

        match *expected == *checksum {
            true => Ok(Self {
                private_key,
                chain_code,
                depth,
                parent_fingerprint,
                child_number,
            }),
            false => Err("Invalid extended private key")
        }
    }
}

impl Display for EthereumExtendedPrivateKey {
    /// BIP32 serialization format: https://github.com/ethereum/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(&[0x04, 0x88, 0xAD, 0xE4][..]);
        result[4] = self.depth as u8;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        BigEndian::write_u32(&mut result[9..13], u32::from(self.child_number));

        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45] = 0;
        result[46..78].copy_from_slice(&self.private_key.secret_key[..]);

        let checksum = &checksum(&result[0..78])[0..4];
        result[78..82].copy_from_slice(&checksum);

        fmt.write_str(&result.to_base58())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn test_from_str(
        expected_secret_key: &str,
        expected_chain_code: &str,
        expected_depth: u8,
        expected_parent_fingerprint: &str,
        expected_child_number: u32,
        expected_xpriv_serialized: &str,
    ) {
        let xpriv = EthereumExtendedPrivateKey::from_str(&expected_xpriv_serialized).expect("error generating xpriv object");
        assert_eq!(expected_secret_key, xpriv.private_key.secret_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(xpriv.chain_code));
        assert_eq!(expected_depth, xpriv.depth);
        assert_eq!(expected_parent_fingerprint, hex::encode(xpriv.parent_fingerprint));
        assert_eq!(expected_child_number, xpriv.child_number);
        assert_eq!(expected_xpriv_serialized, xpriv.to_string());
    }

    fn test_new(
        expected_secret_key: &str,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        expected_xpriv_serialized: &str,
        seed: &str,
    ) {
        let seed_bytes = hex::decode(seed).expect("error decoding hex seed");
        let xpriv = EthereumExtendedPrivateKey::new(&seed_bytes);
        assert_eq!(expected_secret_key, xpriv.private_key.secret_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(xpriv.chain_code));
        assert_eq!(0, xpriv.depth);
        assert_eq!(expected_parent_fingerprint, hex::encode(xpriv.parent_fingerprint));
        assert_eq!(0, xpriv.child_number);
        assert_eq!(expected_xpriv_serialized, xpriv.to_string());
    }

    fn test_to_xpub(expected_xpub_serialized: &str, xpriv: &EthereumExtendedPrivateKey) {
        let xpub = xpriv.to_xpub();
        assert_eq!(expected_xpub_serialized, xpub.to_string());
    }

    fn test_ckd_priv(
        expected_secret_key: &str,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        expected_xpriv_serialized: &str,
        expected_xpub_serialized: &str,
        parent_xpriv: &EthereumExtendedPrivateKey,
        child_number: u32,
    ) -> EthereumExtendedPrivateKey {
        let child_xpriv = parent_xpriv.ckd_priv(child_number);
        assert_eq!(expected_secret_key, child_xpriv.private_key.secret_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(child_xpriv.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(child_xpriv.parent_fingerprint));
        assert_eq!(expected_xpriv_serialized, child_xpriv.to_string());
        assert_eq!(expected_xpub_serialized, child_xpriv.to_xpub().to_string());
        assert_eq!(child_number, child_xpriv.child_number);

        child_xpriv
    }

    fn test_derivation_path(
        expected_secret_key: &str,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        expected_child_number: u32,
        expected_xpriv_serialized: &str,
        expected_xpub_serialized: &str,
        master_xpriv: &EthereumExtendedPrivateKey,
        path: &str,
    ) {
        let derived_xpriv = master_xpriv.derivation_path(path);
        assert_eq!(expected_secret_key, derived_xpriv.private_key.secret_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(derived_xpriv.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(derived_xpriv.parent_fingerprint));
        assert_eq!(expected_child_number, derived_xpriv.child_number);
        assert_eq!(expected_xpriv_serialized, derived_xpriv.to_string());
        assert_eq!(expected_xpub_serialized, derived_xpriv.to_xpub().to_string());
    }

    /// Test vectors from https://en.bitcoin.it/wiki/BIP_0032_TestVectors
    mod bip32_default {
        use super::*;

        // (path, master_seed or child_num, secret_key, chain_code, parent_fingerprint, xpriv, xpub)
        const TEST_VECTOR_1: [(&str, &str, &str, &str, &str, &str, &str); 6] = [
            (
                "m",
                "000102030405060708090a0b0c0d0e0f",
                "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                "00000000",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
            ),
            (
                "m/0'",
                "2147483648",
                "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                "3442193e",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
            ),
            (
                "m/0'/1",
                "1",
                "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
                "5c1bd648",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
            ),
            (
                "m/0'/1/2'",
                "2147483650",
                "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
                "bef5a2f9",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
            ),
            (
                "m/0'/1/2'/2",
                "2",
                "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
                "ee7ab90c",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
            ),
            (
                "m/0'/1/2'/2/1000000000",
                "1000000000",
                "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
                "d880d7d8",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
            )
        ];
        // (path, master_seed or child_num, secret_key, chain_code, parent_fingerprint, xpriv, xpub)
        const TEST_VECTOR_2: [(&str, &str, &str, &str, &str, &str, &str); 6] = [
            (
                "m",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
                "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                "00000000",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
            ),
            (
                "m/0",
                "0",
                "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
                "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                "bd16bee5",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
            ),
            (
                "m/0/2147483647'",
                "4294967295",
                "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
                "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
                "5a61ff8e",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
            ),
            (
                "m/0/2147483647'/1",
                "1",
                "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
                "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
                "d8ab4937",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                "4294967294",
                "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
                "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
                "78412e3a",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                "2",
                "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
                "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
                "31a507b8",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
            )
        ];

        #[test]
        fn test_from_str_tv1() {
            let (
                _,
                _,
                secret_key,
                chain_code,
                parent_fingerprint,
                xpriv_serialized,
                _
            ) = TEST_VECTOR_1[0];
            test_from_str(
                secret_key,
                chain_code,
                0,
                parent_fingerprint,
                0,
                xpriv_serialized,
            );
        }

        #[test]
        fn test_from_str_tv2() {
            let (
                _,
                _,
                secret_key,
                chain_code,
                parent_fingerprint,
                xpriv_serialized,
                _
            ) = TEST_VECTOR_2[0];
            test_from_str(
                secret_key,
                chain_code,
                0,
                parent_fingerprint,
                0,
                xpriv_serialized,
            );
        }

        #[test]
        fn test_new_tv1() {
            let (_,
                seed,
                secret_key,
                chain_code,
                parent_fingerprint,
                xpriv_serialized,
                _
            ) = TEST_VECTOR_1[0];
            test_new(
                secret_key,
                chain_code,
                parent_fingerprint,
                xpriv_serialized,
                seed,
            );
        }

        #[test]
        fn test_new_tv2() {
            let (
                _,
                seed,
                secret_key,
                chain_code,
                parent_fingerprint,
                xpriv_serialized,
                _
            ) = TEST_VECTOR_2[0];
            test_new(
                secret_key,
                chain_code,
                parent_fingerprint,
                xpriv_serialized,
                seed,
            );
        }


        #[test]
        fn test_to_xpub_tv1() {
            let (_, _, _, _, _, xpriv_serialized, xpub_serialized) = TEST_VECTOR_1[0];
            let xpriv = EthereumExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            test_to_xpub(xpub_serialized, &xpriv);
        }

        #[test]
        fn test_to_xpub_tv2() {
            let (_, _, _, _, _, xpriv_serialized, xpub_serialized) = TEST_VECTOR_2[0];
            let xpriv = EthereumExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            test_to_xpub(xpub_serialized, &xpriv);
        }

        #[test]
        fn test_ckd_priv_tv1() {
            let (_, _, _, _, _, xpriv_serialized, _) = TEST_VECTOR_1[0];
            let mut parent_xpriv = EthereumExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            for (_,
                (
                    _,
                    child_number,
                    secret_key,
                    chain_code,
                    parent_fingerprint,
                    xpriv,
                    xpub
                )
            ) in TEST_VECTOR_1[1..].iter_mut().enumerate() {
                let child_number_u32: u32 = child_number.parse().unwrap();
                parent_xpriv = test_ckd_priv(
                    secret_key,
                    chain_code,
                    parent_fingerprint,
                    xpriv,
                    xpub,
                    &parent_xpriv,
                    child_number_u32,
                );
            }
        }

        #[test]
        fn test_ckd_priv_tv2() {
            let (_, _, _, _, _, xpriv_serialized, _) = TEST_VECTOR_2[0];
            let mut parent_xpriv = EthereumExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            for (_,
                (
                    _,
                    child_number,
                    secret_key,
                    chain_code,
                    parent_fingerprint,
                    xpriv,
                    xpub
                )
            ) in TEST_VECTOR_2[1..].iter_mut().enumerate() {
                let child_num_u32: u32 = child_number.parse().unwrap();
                parent_xpriv = test_ckd_priv(
                    secret_key,
                    chain_code,
                    parent_fingerprint,
                    xpriv,
                    xpub,
                    &parent_xpriv,
                    child_num_u32,
                );
            }
        }

        #[test]
        fn test_derivation_path_master() {
            let (_, _, _, _, _, xpriv_master, _) = TEST_VECTOR_1[0];
            let xpriv = EthereumExtendedPrivateKey::from_str(&xpriv_master).unwrap();
            let (
                path,
                _,
                private_key,
                chain_code,
                parent_fingerprint,
                xpriv_serialized,
                xpub_serialized,
            ) = TEST_VECTOR_1[0];

            test_derivation_path(
                private_key,
                chain_code,
                parent_fingerprint,
                0,
                xpriv_serialized,
                xpub_serialized,
                &xpriv,
                path,
            );
        }

        #[test]
        fn test_derivation_path_tv1() {
            let (_, _, _, _, _, xpriv_serialized, _) = TEST_VECTOR_1[0];
            let master_xpriv = EthereumExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            for (_,
                (
                    path,
                    child_number,
                    secret_key,
                    chain_code,
                    parent_fingerprint,
                    xpriv_serialized,
                    xpub_serialized
                )
            ) in TEST_VECTOR_1[1..].iter_mut().enumerate() {
                let child_number_u32: u32 = child_number.parse().unwrap();
                test_derivation_path(
                    secret_key,
                    chain_code,
                    parent_fingerprint,
                    child_number_u32,
                    &xpriv_serialized,
                    &xpub_serialized,
                    &master_xpriv,
                    path,
                );
            }
        }

        #[test]
        fn test_derivation_path_tv2() {
            let (_, _, _, _, _, xpriv_serialized, _) = TEST_VECTOR_2[0];
            let master_xpriv = EthereumExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            for (_,
                (
                    path,
                    child_number,
                    secret_key,
                    chain_code,
                    parent_fingerprint,
                    xpriv_serialized,
                    xpub_serialized
                )
            ) in TEST_VECTOR_2[1..].iter_mut().enumerate() {
                let child_number_u32: u32 = child_number.parse().unwrap();
                test_derivation_path(
                    secret_key,
                    chain_code,
                    parent_fingerprint,
                    child_number_u32,
                    &xpriv_serialized,
                    &xpub_serialized,
                    &master_xpriv,
                    path,
                );
            }
        }
    }

    mod bip44 {
        use super::*;

        /// Test case from ethereumjs-wallet https://github.com/ethereumjs/ethereumjs-wallet/blob/master/src/test/hdkey.js
        #[test]
        fn test_derivation_path() {
            let path = "m/44'/0'/0/1";
            let expected_xpriv = "xprvA1ErCzsuXhpB8iDTsbmgpkA2P8ggu97hMZbAXTZCdGYeaUrDhyR8fEw47BNEgLExsWCVzFYuGyeDZJLiFJ9kwBzGojQ6NB718tjVJrVBSrG";
            let master_xpriv = EthereumExtendedPrivateKey::from_str("xprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY").unwrap();
            let xpriv = master_xpriv.derivation_path(path);
            assert_eq!(expected_xpriv, xpriv.to_string());
        }
    }
}
use crate::address::BitcoinAddress;
use crate::derivation_path::BitcoinDerivationPath;
use crate::extended_public_key::BitcoinExtendedPublicKey;
use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use crate::private_key::BitcoinPrivateKey;
use crate::public_key::BitcoinPublicKey;
use wagyu_model::{
    crypto::{checksum, hash160},
    AddressError, ChildIndex, DerivationPath, ExtendedPrivateKey, ExtendedPrivateKeyError, ExtendedPublicKey,
    PrivateKey,
};

use base58::{FromBase58, ToBase58};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha512;
use std::{convert::TryFrom, fmt, fmt::Display, str::FromStr};

type HmacSha512 = Hmac<Sha512>;

/// Represents a Bitcoin extended private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitcoinExtendedPrivateKey<N: BitcoinNetwork> {
    /// The address format
    pub(super) format: BitcoinFormat,
    /// The depth of key derivation, e.g. 0x00 for master nodes, 0x01 for level-1 derived keys, ...
    pub(super) depth: u8,
    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    pub(super) parent_fingerprint: [u8; 4],
    /// The child index of the key (0 for master key)
    pub(super) child_index: ChildIndex,
    /// The chain code for this extended private key
    pub(super) chain_code: [u8; 32],
    /// The Bitcoin private key
    private_key: BitcoinPrivateKey<N>,
}

impl<N: BitcoinNetwork> ExtendedPrivateKey for BitcoinExtendedPrivateKey<N> {
    type Address = BitcoinAddress<N>;
    type DerivationPath = BitcoinDerivationPath<N>;
    type ExtendedPublicKey = BitcoinExtendedPublicKey<N>;
    type Format = BitcoinFormat;
    type PrivateKey = BitcoinPrivateKey<N>;
    type PublicKey = BitcoinPublicKey<N>;

    /// Returns a new Bitcoin extended private key.
    fn new(seed: &[u8], format: &Self::Format, path: &Self::DerivationPath) -> Result<Self, ExtendedPrivateKeyError> {
        Ok(Self::new_master(seed, format)?.derive(path)?)
    }

    /// Returns a new Bitcoin extended private key.
    fn new_master(seed: &[u8], format: &Self::Format) -> Result<Self, ExtendedPrivateKeyError> {
        let mut mac = HmacSha512::new_varkey(b"Bitcoin seed")?;
        mac.input(seed);
        let hmac = mac.result().code();
        let private_key = Self::PrivateKey::from_secp256k1_secret_key(SecretKey::from_slice(&hmac[0..32])?, true);

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&hmac[32..]);

        Ok(Self {
            format: format.clone(),
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: ChildIndex::Normal(0),
            chain_code,
            private_key,
        })
    }

    /// Returns the extended private key of the given derivation path.
    fn derive(&self, path: &Self::DerivationPath) -> Result<Self, ExtendedPrivateKeyError> {
        if self.depth == 255 {
            return Err(ExtendedPrivateKeyError::MaximumChildDepthReached(self.depth));
        }

        let mut extended_private_key = self.clone();

        for index in path.to_vec()?.into_iter() {
            let public_key = &PublicKey::from_secret_key(
                &Secp256k1::new(),
                &extended_private_key.private_key.to_secp256k1_secret_key(),
            )
            .serialize()[..];

            let mut mac = HmacSha512::new_varkey(&extended_private_key.chain_code)?;
            match index {
                // HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
                ChildIndex::Normal(_) => mac.input(public_key),
                // HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i))
                // (Note: The 0x00 pads the private key to make it 33 bytes long.)
                ChildIndex::Hardened(_) => {
                    mac.input(&[0u8]);
                    mac.input(&extended_private_key.private_key.to_secp256k1_secret_key()[..]);
                }
            }
            // Append the child index in big-endian format
            mac.input(&u32::from(index).to_be_bytes());
            let hmac = mac.result().code();

            let mut secret_key = SecretKey::from_slice(&hmac[0..32])?;
            secret_key.add_assign(&extended_private_key.private_key.to_secp256k1_secret_key()[..])?;
            let private_key = Self::PrivateKey::from_secp256k1_secret_key(secret_key, true);

            let mut chain_code = [0u8; 32];
            chain_code[0..32].copy_from_slice(&hmac[32..]);

            let mut parent_fingerprint = [0u8; 4];
            parent_fingerprint.copy_from_slice(&hash160(public_key)[0..4]);

            extended_private_key = Self {
                format: extended_private_key.format.clone(),
                depth: extended_private_key.depth + 1,
                parent_fingerprint,
                child_index: index,
                chain_code,
                private_key,
            }
        }

        Ok(extended_private_key)
    }

    /// Returns the extended public key of the corresponding extended private key.
    fn to_extended_public_key(&self) -> Self::ExtendedPublicKey {
        Self::ExtendedPublicKey::from_extended_private_key(&self)
    }

    /// Returns the private key of the corresponding extended private key.
    fn to_private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }

    /// Returns the public key of the corresponding extended private key.
    fn to_public_key(&self) -> Self::PublicKey {
        self.private_key.to_public_key()
    }

    /// Returns the address of the corresponding extended private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        self.private_key.to_address(format)
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinExtendedPrivateKey<N> {
    type Err = ExtendedPrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58()?;
        if data.len() != 82 {
            return Err(ExtendedPrivateKeyError::InvalidByteLength(data.len()));
        }

        // Check that the version bytes correspond with the correct network.
        let _ = N::from_extended_private_key_version_bytes(&data[0..4])?;
        let format = BitcoinFormat::from_extended_private_key_version_bytes(&data[0..4])?;

        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_index = ChildIndex::from(u32::from_be_bytes(<[u8; 4]>::try_from(&data[9..13])?));

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let private_key = BitcoinPrivateKey::from_secp256k1_secret_key(SecretKey::from_slice(&data[46..78])?, true);

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(ExtendedPrivateKeyError::InvalidChecksum(expected, found));
        }

        Ok(Self {
            format,
            depth,
            parent_fingerprint,
            child_index,
            chain_code,
            private_key,
        })
    }
}

impl<N: BitcoinNetwork> Display for BitcoinExtendedPrivateKey<N> {
    /// BIP32 serialization format
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(match &N::to_extended_private_key_version_bytes(&self.format) {
            Ok(version) => version,
            Err(_) => return Err(fmt::Error),
        });
        result[4] = self.depth;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        result[9..13].copy_from_slice(&u32::from(self.child_index).to_be_bytes());
        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45] = 0;
        result[46..78].copy_from_slice(&self.private_key.to_secp256k1_secret_key()[..]);

        let checksum = &checksum(&result[0..78])[0..4];
        result[78..82].copy_from_slice(&checksum);

        fmt.write_str(&result.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;

    use hex;
    use std::convert::TryInto;
    use std::string::String;

    fn test_new<N: BitcoinNetwork>(
        expected_extended_private_key: &str,
        expected_parent_fingerprint: &str,
        expected_child_index: u32,
        expected_chain_code: &str,
        expected_secret_key: &str,
        seed: &str,
        format: &BitcoinFormat,
        path: &BitcoinDerivationPath<N>,
    ) {
        let extended_private_key =
            BitcoinExtendedPrivateKey::<N>::new(&hex::decode(seed).unwrap(), format, path).unwrap();
        assert_eq!(expected_extended_private_key, extended_private_key.to_string());
        assert_eq!(
            expected_parent_fingerprint,
            hex::encode(extended_private_key.parent_fingerprint)
        );
        assert_eq!(expected_child_index, u32::from(extended_private_key.child_index));
        assert_eq!(expected_chain_code, hex::encode(extended_private_key.chain_code));
        assert_eq!(
            expected_secret_key,
            extended_private_key.private_key.to_secp256k1_secret_key().to_string()
        );
    }

    // Check: (extended_private_key1 -> extended_private_key2) == (expected_extended_private_key2)
    fn test_derive<N: BitcoinNetwork>(
        expected_extended_private_key1: &str,
        expected_extended_private_key2: &str,
        expected_child_index2: u32,
    ) {
        let path = vec![ChildIndex::from(expected_child_index2)].try_into().unwrap();

        let extended_private_key1 = BitcoinExtendedPrivateKey::<N>::from_str(expected_extended_private_key1).unwrap();
        let extended_private_key2 = extended_private_key1.derive(&path).unwrap();

        let expected_extended_private_key2 =
            BitcoinExtendedPrivateKey::<N>::from_str(&expected_extended_private_key2).unwrap();

        assert_eq!(expected_extended_private_key2, extended_private_key2);
        assert_eq!(
            expected_extended_private_key2.private_key,
            extended_private_key2.private_key
        );
        assert_eq!(expected_extended_private_key2.depth, extended_private_key2.depth);
        assert_eq!(
            expected_extended_private_key2.child_index,
            extended_private_key2.child_index
        );
        assert_eq!(
            expected_extended_private_key2.chain_code,
            extended_private_key2.chain_code
        );
        assert_eq!(
            expected_extended_private_key2.parent_fingerprint,
            extended_private_key2.parent_fingerprint
        );
    }

    fn test_to_extended_public_key<N: BitcoinNetwork>(
        expected_extended_public_key: &str,
        seed: &str,
        format: &BitcoinFormat,
        path: &BitcoinDerivationPath<N>,
    ) {
        let extended_private_key =
            BitcoinExtendedPrivateKey::<N>::new(&hex::decode(seed).unwrap(), format, path).unwrap();
        let extended_public_key = extended_private_key.to_extended_public_key();
        assert_eq!(expected_extended_public_key, extended_public_key.to_string());
    }

    fn test_from_str<N: BitcoinNetwork>(
        expected_extended_private_key: &str,
        expected_parent_fingerprint: &str,
        expected_child_index: u32,
        expected_chain_code: &str,
        expected_secret_key: &str,
    ) {
        let extended_private_key = BitcoinExtendedPrivateKey::<N>::from_str(expected_extended_private_key).unwrap();
        assert_eq!(expected_extended_private_key, extended_private_key.to_string());
        assert_eq!(
            expected_parent_fingerprint,
            hex::encode(extended_private_key.parent_fingerprint)
        );
        assert_eq!(expected_child_index, u32::from(extended_private_key.child_index));
        assert_eq!(expected_chain_code, hex::encode(extended_private_key.chain_code));
        assert_eq!(
            expected_secret_key,
            extended_private_key.private_key.to_secp256k1_secret_key().to_string()
        );
    }

    fn test_to_string<N: BitcoinNetwork>(expected_extended_private_key: &str) {
        let extended_private_key = BitcoinExtendedPrivateKey::<N>::from_str(expected_extended_private_key).unwrap();
        assert_eq!(expected_extended_private_key, extended_private_key.to_string());
    }

    mod p2pkh_mainnet {
        use super::*;

        type N = Mainnet;

        // (path, seed, child_index, secret_key, chain_code, parent_fingerprint, extended_private_key, extended_public_key)
        const KEYPAIRS: [(&str, &str, &str, &str, &str, &str, &str, &str); 26] = [

            // BIP32 Derivation Paths
            (
                "m",
                "000102030405060708090a0b0c0d0e0f",
                "0",
                "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                "00000000",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
            ),
            (
                "m/0'",
                "000102030405060708090a0b0c0d0e0f",
                "2147483648",
                "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                "3442193e",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
            ),
            (
                "m/0'/1",
                "000102030405060708090a0b0c0d0e0f",
                "1",
                "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
                "5c1bd648",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
            ),
            (
                "m/0'/1/2'",
                "000102030405060708090a0b0c0d0e0f",
                "2147483650",
                "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
                "bef5a2f9",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
            ),
            (
                "m/0'/1/2'/2",
                "000102030405060708090a0b0c0d0e0f",
                "2",
                "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
                "ee7ab90c",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
            ),
            (
                "m/0'/1/2'/2/1000000000",
                "000102030405060708090a0b0c0d0e0f",
                "1000000000",
                "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
                "d880d7d8",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
            ),
            (
                "m",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "0",
                "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
                "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                "00000000",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
            ),
            (
                "m/0",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "0",
                "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
                "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                "bd16bee5",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
            ),
            (
                "m/0/2147483647'",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "4294967295",
                "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
                "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
                "5a61ff8e",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
            ),
            (
                "m/0/2147483647'/1",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "1",
                "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
                "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
                "d8ab4937",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "4294967294",
                "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
                "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
                "78412e3a",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "2",
                "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
                "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
                "31a507b8",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
            ),

            // BIP 44 Derivation Paths
            (
                "m/44'/0'/0'/0",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "0",
                "4338d5f49fecfe380b9e60e032b7da0845e7f9d441ac78bd58ab1af423187d7d",
                "c2c14ca7969bfea1753c39eb5238cb948dc3202478b414e0e924e7a21f4fe654",
                "929c7e3c",
                "xprvA1d47WXmiQZzV33ywwsbBhbtLg7f9XzMv6xdEbP6yJSxw38RhQzarwW3GDKvYnfvY67fWjEsF5ySDnXZ9sVwsw9A7sYE1gTBKkTkhxM3Foz",
                "xpub6EcQX24fYn8HhX8T3yQbYqYcthx9YziDHKtE2yniXdywoqTaExJqQjpX7WwBmeVH2D3U8CXiADcvBHSCQ3UKNUxh2w8pZFNAnjEFD89Qh1x"
            ),
            (
                "m/44'/0'/0'/0/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "0075bcd6a7c659d8336141ad6a3103a34a9a3a5a6dfdcab7df9670646f0b6761",
                "c96ae85842d7d557c15a09e19286475ede2b895b91a277a4c624a974b0a3811d",
                "09d96c42",
                "xprvA2VtPkeWPbFDHmZhGCEcFMX65Xmrp1iSA3zWbqXKDfJnBHzqZHdBbDeJQdt6KVYTftnXVWTaDS1b59etrug5kJRLFQjtKyzvKaCyti9gkU3",
                "xpub6FVEoGBQDxoWWFeANDmccVTpdZcMDUSHXGv7QDvvmzqm46Kz6pwS91xnFwNnL8T9c7nLCH54EQ13ADTwjGuNDCFVsRmSWKCgcejAQES4Eyu"
            ),
            (
                "m/44'/0'/0'/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "f29d6ddd6b0cd1fd59ed99900edd5a53e905b87dfe06824751010feb5228d960",
                "0674ec59dbc724f29fea71d771b62aba454732067055e3d29fe640c3c4cef2a4",
                "929c7e3c",
                "xprvA1d47WXmiQZzVi9TCYLCjYPsi5t1iTdFqsxh1BRjQM773CPwhnwEruxGViVVXqPcyP3NYQroJjHNjUG1WFKgDPNB97F5SFUtKpECsNSskGZ",
                "xpub6EcQX24fYn8HiCDvJZsD6gLcG7iW7vM7D6tHoZqLxge5uzj6FLFVQiGkLyZbHbQE7otB7LfSYsbJnNbxyjGnr1ubGC2XfTXXwH86Nf6p5DF"
            ),
            (
                "m/44'/0'/0'/1/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "41429c1338d0b8b0a3ef984f02b9e0f05100e45f4c639937191e400345402764",
                "e35471cdbd74303352b18df7efbfc0144da3cb416f8cc15ea90ca18357e89607",
                "411064ed",
                "xprvA2uRdfuKqiFoqcU4BrnVttrwRbg4mJCBgwAuGqNh8rAZB2uge9sNUh9UQtQ1Xfjsys6V38yfn3PcNvupTm6kpDBscEAfVTMWCQeMdQxUgTD",
                "xpub6Ftn3BSDg5p746YXHtKWG2ofydWZAkv34A6W5DnJhBhY3qEqBhBd2VTxGArPq7BjJRjKmvWHN8chjNLchv3xFh5Xc7Vut8DNvXPvErVtMzE"
            ),
            (
                "m/44'/0'/1'/0",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "0",
                "95ee1cfd2375843a1f4e59af8e6ca43c179bf19779b188031ccc9285dbea8073",
                "2f87b7dcaa60ad05af4f207f1e5c336b0727eaf5bbe80aa555e5e725d58b45fa",
                "67384ff6",
                "xprvA1JZDdbTugxrS1djWVMi4PBwuj3ZQpbBU8svUHAJvXmpPhBiEPmdpbZ5gqP6R6ZPKT6oLa7g63NzLHZPPvxbNuL9fp3Cb4dVgrWPpKnSpYi",
                "xpub6EHud98Mk4X9eViCcWtiRX8gTkt3pHK2qMoXGfZvUsJoGVWrmw5tNPsZY89jdJxruFzNAx21AHDXNBKZq26rvTadEUJzr3N681oCMdPvCti"
            ),
            (
                "m/44'/0'/1'/0/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "dec327ab861f7b4da1ea67b45516f0b6d71b93ba4f3de22dd2b1e12203ca1f02",
                "976331516208a95719780daaaaaff9dbd22665cf17370009abbbb4855569cf89",
                "c014feb5",
                "xprvA3qaHECwxhyhico68CLW3Ea3AYqySdqMF3VpkD4u3myo5PFM1CbX4cgLW854YRu6caycEjFiiBWDzxYBq4hhWRMCf73JTMRPCCPzHFRAfRv",
                "xpub6Gpvgjjqo5Xzw6sZEDsWQNWmiagTr6ZCcGRRYbUWc7WmxBaVYjumcQzpMNPYRnRq3amgFU4wBLmEgc2Q4RMSuVsTcDTsYTM9sS531imfqu9"
            ),
            (
                "m/44'/0'/1'/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "b86188deda09b95d38290624b326f36e233ad87c7b74fdabaa0078f5187b0838",
                "6ebc69c29028acba7b300da6f21f3482bb99cb13948f4d95e63e18478135e55f",
                "67384ff6",
                "xprvA1JZDdbTugxrVBxbzConV3CE4EhxEtr2j5fxeZwCSuWTZu9zwYmJpUyccKVpN1M3RjozbZugobPpECXN1vFcZPh6T5X4545Z6PaaaVqzxhw",
                "xpub6EHud98Mk4X9hg356ELnrB8xcGYSeMZt6JbZSxLp1F3SShV9V65ZNHJ6TbPy5otasZ7HTgTC4CL27FEB4qMiuTfqTFwuHTNHZubbseiZ7eG"
            ),
            (
                "m/44'/0'/1'/1/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "398ade967bd6c3e7131647a5f819746624e419eae739d757bde2506fc0aec8bf",
                "19debf400dd10bfe2b72813a7e21cde2dba9f9830c5b5264d4f6c11f52814086",
                "b4a881d9",
                "xprvA3khpHeVPioNS7K9GYyRATZjy5fUuGC6kfC8hqafn5dt6AGttDjMdXDmGZJxqaqGRJEfSwgDKh4cLengDF5jhVdsutdK8p4skfYjjgFVJKs",
                "xpub6Gk4DoBPE6MfebPcNaWRXbWUX7VyJiux7t7jWDzHLRArxxc3Rm3cBKYF7qJdsM25tGn757PavnGhAiQxToSzDxx7eGukDY5WQEhAL7fb3Ar"
            ),

            // Bitcoin Core Derivation Paths
            (
                "m/0'/0'",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "2147483648",
                "f0ba40d643ad82ccf5b6228cd0b723144d6a2b6af3daec5c57631f54b4619e77",
                "7db48bfda81e8d1c18aa9f8649dea892c8abea84d54d0c0e895857c16fc585df",
                "2b889e8f",
                "xprv9w6qhRqTDF9JBxEwxukUTL6Yi24XZ5sYyGZAoR3LtzT9BBrnz72HibYxcQnQMCEEyGMLDSubfSCufC8H5sFCzofrkGa4GhskZrYxW6anz1P",
                "xpub6A6C6wNM3chbQSKR4wHUpU3HG3u1xYbQLVUmboSxTKz83zBwXeLYGPsSTgBXeXE3Lkaf5M9oCPKwg3WxJZHqA35R7WVYkZyAUYq4xJNq5fy"
            ),
            (
                "m/0'/0'/0'",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "2147483648",
                "b33f5ac29e0b36a65ed527e8f7d394a33a6767031e68afe6df8f366c09547e30",
                "3601dd1853197d38d4f9d4f8b5cbbc4d2062768dc6279c68b2bd085345ca71f2",
                "2e494d03",
                "xprv9y19cq5eXQFfNDsNmLKiYMxPPN4odkFfRmL1RqJEheTMtHFVY8vm1xWYkCN6Zznp13m34qxbc9S2LXhd56Vk1P3qnURBmTg4B2dpkMs9Gzv",
                "xpub6BzW2LcYMmoxahwqsMriuVu7wPuJ3CyWnzFcEDhrFyzLm5ae5gF1Zkq2bSR4U1S6psBQzosfXAFqSb9YzHvd6LVAe7fHgtkjPKM8wPBhyRk"
            ),

            // Multibit Derivation Paths
            (
                "m/0'/0",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "0",
                "74d29dfbbc821a973c87ec53ff446369cb4639ad6a4c74e08ec771d052c56ccf",
                "402baa6c2837a364e0ee384afd99a339a9f01b68c42eba5fd840a7475392e87b",
                "2b889e8f",
                "xprv9w6qhRqJsacL14RFPYGwMtGPnCrRaRdW97quivF9gFzy2Gzu4zxrwr65KRUzBDGmbLr61jnAQkvrz4wu7UApPPTSZfq7NZUndMPWrJ5LRty",
                "xpub6A6C6wNChxAdDYViVZowj2D8LEguytMMWLmWXJemEbXwu5L3cYH7VeQZAgSWtrGQ783strAoBQrSTpfUxnf2QaSC9ExhuXDEooZGKWrUkey"
            ),
            (
                "m/0'/0/0",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "0",
                "05b232fd66616e350c2db176aa650f3f642df22e0efb7831d5c3ee5206639cdb",
                "fd9a583afe8f38d077335f4bdf96146070782581aa174bf2ade5a7009e6247f6",
                "c677886d",
                "xprv9z82SKRcnNidyodMRmo4T96QD481VWNAxK7LgJghFdgDvsc95AuBFbjUuqhzkynYgx2ay1VN5J6yAUwpCPo4L9pjUoX1HwNx9xBFKR4y8yv",
                "xpub6D7NqpxWckGwCHhpXoL4pH38m5xVty62KY2wUh6JoyDCofwHciDRoQ3xm7WAg2ffpHaC6X4bEociYq81niyNUGhCxEs6fDFAd1LPbEmzcAm"
            ),

            // Block Explorer Derivation Paths (example: blockchain.info)
            (
                "m/44'/0'/0'",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "2147483648",
                "47beaf6a6be527c151297bba99b3da1cd02fa88f6278d550cd5a282123283c9f",
                "d4297bd8126147c4da781f78af3d5e92992fb799a0fa73cb254bfc5b4358167d",
                "88d9ebc3",
                "xprv9yfkvkuXqXhVbpVNpCoEPUUxZfKPC51DPDMYEWmmbYChi8ovEmcwnVQpFAjgXXjuoRkCDy3iJkyndER6XrLWCf7v2BcsoVdbuNER96UuU5H",
                "xpub6Cf7LGSRfuFnpJZqvELEkcRh7h9sbXj4kSH92uBP9sjgaw94nJwCLHjJ6SnnqpLtYmdencmUKm91AMWWZAqEPYUKVvWso4M572aRrm7NGxV"
            ),
            (
                "m/44'/0'/0'/0",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "0",
                "4338d5f49fecfe380b9e60e032b7da0845e7f9d441ac78bd58ab1af423187d7d",
                "c2c14ca7969bfea1753c39eb5238cb948dc3202478b414e0e924e7a21f4fe654",
                "929c7e3c",
                "xprvA1d47WXmiQZzV33ywwsbBhbtLg7f9XzMv6xdEbP6yJSxw38RhQzarwW3GDKvYnfvY67fWjEsF5ySDnXZ9sVwsw9A7sYE1gTBKkTkhxM3Foz",
                "xpub6EcQX24fYn8HhX8T3yQbYqYcthx9YziDHKtE2yniXdywoqTaExJqQjpX7WwBmeVH2D3U8CXiADcvBHSCQ3UKNUxh2w8pZFNAnjEFD89Qh1x"
            )
        ];

        #[test]
        fn new() {
            KEYPAIRS.iter().for_each(
                |(path, seed, child_index, secret_key, chain_code, parent_fingerprint, extended_private_key, _)| {
                    test_new::<N>(
                        extended_private_key,
                        parent_fingerprint,
                        child_index.parse().unwrap(),
                        chain_code,
                        secret_key,
                        seed,
                        &BitcoinFormat::P2PKH,
                        &BitcoinDerivationPath::from_str(path).unwrap(),
                    );
                },
            );
        }

        #[test]
        fn derive() {
            KEYPAIRS.chunks(2).for_each(|pair| {
                let (_, _, _, _, _, _, expected_extended_private_key1, _) = pair[0];
                let (_, _, expected_child_index2, _, _, _, expected_extended_private_key2, _) = pair[1];
                test_derive::<N>(
                    expected_extended_private_key1,
                    expected_extended_private_key2,
                    expected_child_index2.parse().unwrap(),
                );
            });
        }

        #[test]
        fn to_extended_public_key() {
            KEYPAIRS
                .iter()
                .for_each(|(path, seed, _, _, _, _, _, expected_public_key)| {
                    test_to_extended_public_key::<N>(
                        expected_public_key,
                        seed,
                        &BitcoinFormat::P2PKH,
                        &BitcoinDerivationPath::from_str(path).unwrap(),
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(
                |(_, _, child_index, secret_key, chain_code, parent_fingerprint, extended_private_key, _)| {
                    test_from_str::<N>(
                        extended_private_key,
                        parent_fingerprint,
                        child_index.parse().unwrap(),
                        chain_code,
                        secret_key,
                    );
                },
            );
        }

        #[test]
        fn to_string() {
            KEYPAIRS.iter().for_each(|(_, _, _, _, _, _, extended_private_key, _)| {
                test_to_string::<N>(extended_private_key);
            });
        }
    }

    mod p2sh_p2wpkh_mainnet {
        use super::*;

        type N = Mainnet;

        // (path, seed, child_index, secret_key, chain_code, parent_fingerprint, extended_private_key, extended_public_key)
        const KEYPAIRS: [(&str, &str, &str, &str, &str, &str, &str, &str); 8] = [

            // BIP49 Derivation Paths
            (
                "m/49'/0'/0'/0",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "0",
                "00488e6935838afba847d9c12ed643fce921c87454418c2c5e4ac82bdf9ff351",
                "6ce0dcd808c9ce2ac36191162f5b68b6b9c1319c9a7f2a55b8438b24ea061e91",
                "ed088f15",
                "yprvAM7sCKyfKPFyPT1kyKsHWEoWqJPKTAwgyRrVZLe3RaX6dd5EK1NE87WYsi3yGisqGsJoQ21v7WUercQsUdST2HeV91poWQY5mGrk4yWnuy5",
                "ypub6a7DbqWZ9kpGbw6E5MQHsNkFPLDordfYLen6Mj3eyv45WRQNrYgUfuq2izWkWnBbFsv7vHcPbs2gzJwEYqRobMGiJVFqSAm9w8jiKXYNV92"
            ),
            (
                "m/49'/0'/0'/0/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "128316419b0dcca64fa60960a8fcd633539bc18322636e03d1e5c3c576135d22",
                "b3bc049be87695ae3bd66e12ab37bc629a3f7d8c59c4b1fb69250f9dd0f60b22",
                "226587c8",
                "yprvAMWceuThEayAsqgfGZcWQHBPMobihTywY7GTXtFikg64qqjqC5xxMuSz6jdFpo5ArMjRMui5fMX9E9GToPXJqg8bMpZzyPzbm9fJxUYPVu5",
                "ypub6aVy4Qzb4xXU6Km8Nb9WmR87uqSD6vhnuLC4LGfLK1d3ie4yjdHCuhmTx2RPAJwrZaAXpqhDWJ3pM5VmjzvTcJNAqNHfvxVcaXT3h1VXR5b"
            ),
            (
                "m/49'/0'/0'/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "b962720ba4e38e3cea5b7c5e4582bde83641cf2a153e60ae8fd4bb7711645aa5",
                "d532957b2cfb9d5d640494d17f216011f35e1fc0a6b574e16d222075d86ec2c1",
                "ed088f15",
                "yprvAM7sCKyfKPFyT35btaVetbAMNSxBAiX9QAqPQQPytDwVD3ddBsxMbUf9MzVUfJMzFsPaTes5qYe8cp9pGXfZycs5dp8frX6NC3HYnXHnKun",
                "ypub6a7DbqWZ9kpGfXA4zc2fFj75vUnfaBEzmPkzCnobSZUU5qxmjRGc9GydDFP8kUUddcazkH5nrPi4nT3QbQ4SQTj2jEsnZ2EXFsB7qvoxExH"
            ),
            (
                "m/49'/0'/0'/1/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "9db56d12672cd6adcabc637dcc23ce19813b28c8812226153f3bae1c72d62877",
                "b149f3908b23ec6af124c9237d902a0e83e44d10a9043950785ae7129e70a57b",
                "854920fd",
                "yprvANEmnYaG6PyXCHrLbJ9vDpjQpc145pqmH9H2biR7B5xDgVoRTKMUjXhGQPbPcDUo7TuY6VryGxpe9YwB3JM8MaK4P1MtEkctwxZahrSkTjt",
                "ypub6bE8C479vmXpQmvohKgvaxg9NdqYVHZceNCdQ6pijRVCZJ8ZzrfjHL1kFfPNPdDj9Xmd2ntEXqJ3UsmWd74NQt2kpAzTpTWjH4HrCcb4kbD"
            ),
            (
                "m/49'/0'/1'/0",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "0",
                "1c8b1cb1af5d7ec0f7c5bff350bbad9c62d81751b50a434941001ef50c422edd",
                "7f8790af54660ad2c31a0d4854f462e74c56eabf89c23c015daf2557dd22c805",
                "c4bd345b",
                "yprvALpgsrPPYqg9VeEVcvVnzjTvBRGJk1FPAZh4rMcBpKAHNavJJKzJPeQMbYpWHgR54DQUiQ6MaVKXxELVQXcHpM2QyajifGoGyxaJCEXKUU1",
                "ypub6Zp3HMvHPDESi8Jxix2oMsQejT6o9TyEXncfek1oNehGFPFSqsJYwSiqSpT65DYQyqDUUsrLg2saWwcMkdNGdVGt67gCv7ycXfvw3RUCWJc"
            ),
            (
                "m/49'/0'/1'/0/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "078e5b6108f5171b9514bbe42b371fcae78332de86d6a8c377fc350c6761f649",
                "4926d4cf1f0e246e5e84b51a564889350c8ce9d0f9357f5e925a89ced2b384d1",
                "0bffe647",
                "yprvAMM4sBZ5DwaqiWMcdoxmMS736ixPeDPeUdzusQkPFXcYJtsLSpNmuwaXibu3pRfYaTDZ9o6Pv8wWacVBLPNGyp9XPF9ETX7cc4KjMdZmBBw",
                "ypub6aLRGh5y4K98vzS5jqVmia3meknt3g7VqrvWfo9zos9XBhCUzMh2Tju1ZtkQRMpHi42tDYXUvJR46exugN8Gz1kxu3zpuckVR444tE6t89L"
            ),
            (
                "m/49'/0'/1'/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "d2d6415f3a8533dbf3c2a930553bafb97c0c21782f65fa218ccc46a8cde16aa1",
                "97acdd147742d49c9bbe2ed118152f1501c0159009450bc16f7c2cacef085e97",
                "c4bd345b",
                "yprvALpgsrPPYqg9YS1AATRMs4e8p5KDoGTdsB3PRcebfgFmc8idEFDwoGUzcqEgBtoB1TeLzWKN9y8wpb8so57f2uq1QvuXoqZHiNGKY7CKJWH",
                "ypub6Zp3HMvHPDESkv5dGUxNECasN79iCjBVEPxzE14DE1nkUw3mmnYCM4oUU88wfKVginVPsPax4MZxuEmgxAwcH48PKLUxqGh2ZBaFgPQWczF"
            ),
            (
                "m/49'/0'/1'/1/1",
                "747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03",
                "1",
                "7cee168da33dad928d22d0d629d88c74d20ea02b5d1ae742d97e98e9f6b9a2a3",
                "d9ccf85ebdf4308622b63da49d3017f0fcb1e7c5c32d46c998291a5a5a082368",
                "e1a183e9",
                "yprvANv97foamnucG4mLwkifvFmEez9XDYfmFH3tUWh4U16Qsau6KmwZ7iRyu4byPtYTFfeFv9i3hK472wkNH8ZK2667RoR9mEyNCK1HimnKv9h",
                "ypub6buVXBLUcATuUYqp3nFgHPhyD1z1d1PccVyVGu6g2LdPkPEEsKFofWkTkLM4YeWoQDwEfsezCmjJbqjr6Tajv7Q8ktnHFkE3FiaS7fUFyYh"
            ),
        ];

        #[test]
        fn new() {
            KEYPAIRS.iter().for_each(
                |(path, seed, child_index, secret_key, chain_code, parent_fingerprint, extended_private_key, _)| {
                    test_new::<N>(
                        extended_private_key,
                        parent_fingerprint,
                        child_index.parse().unwrap(),
                        chain_code,
                        secret_key,
                        seed,
                        &BitcoinFormat::P2SH_P2WPKH,
                        &BitcoinDerivationPath::from_str(path).unwrap(),
                    );
                },
            );
        }

        #[test]
        fn derive() {
            KEYPAIRS.chunks(2).for_each(|pair| {
                let (_, _, _, _, _, _, expected_extended_private_key1, _) = pair[0];
                let (_, _, expected_child_index2, _, _, _, expected_extended_private_key2, _) = pair[1];
                test_derive::<N>(
                    expected_extended_private_key1,
                    expected_extended_private_key2,
                    expected_child_index2.parse().unwrap(),
                );
            });
        }

        #[test]
        fn to_extended_public_key() {
            KEYPAIRS
                .iter()
                .for_each(|(path, seed, _, _, _, _, _, expected_public_key)| {
                    test_to_extended_public_key::<N>(
                        expected_public_key,
                        seed,
                        &BitcoinFormat::P2SH_P2WPKH,
                        &BitcoinDerivationPath::from_str(path).unwrap(),
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(
                |(_, _, child_index, secret_key, chain_code, parent_fingerprint, extended_private_key, _)| {
                    test_from_str::<N>(
                        extended_private_key,
                        parent_fingerprint,
                        child_index.parse().unwrap(),
                        chain_code,
                        secret_key,
                    );
                },
            );
        }

        #[test]
        fn to_string() {
            KEYPAIRS.iter().for_each(|(_, _, _, _, _, _, extended_private_key, _)| {
                test_to_string::<N>(extended_private_key);
            });
        }
    }

    mod test_invalid {
        use super::*;

        type N = Mainnet;

        const INVALID_EXTENDED_PRIVATE_KEY_SECP256K1_SECRET_KEY: &str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW";
        const INVALID_EXTENDED_PRIVATE_KEY_NETWORK: &str = "xprv8s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        const INVALID_EXTENDED_PRIVATE_KEY_CHECKSUM: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHj";
        const VALID_EXTENDED_PRIVATE_KEY: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        #[test]
        #[should_panic(expected = "Crate(\"secp256k1\", \"InvalidSecretKey\")")]
        fn from_str_invalid_secret_key() {
            let _result =
                BitcoinExtendedPrivateKey::<N>::from_str(INVALID_EXTENDED_PRIVATE_KEY_SECP256K1_SECRET_KEY).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidVersionBytes([4, 136, 173, 227])")]
        fn from_str_invalid_version() {
            let _result = BitcoinExtendedPrivateKey::<N>::from_str(INVALID_EXTENDED_PRIVATE_KEY_NETWORK).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidChecksum(\"6vCfku\", \"6vCfkt\")")]
        fn from_str_invalid_checksum() {
            let _result = BitcoinExtendedPrivateKey::<N>::from_str(INVALID_EXTENDED_PRIVATE_KEY_CHECKSUM).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(81)")]
        fn from_str_short() {
            let _result = BitcoinExtendedPrivateKey::<N>::from_str(&VALID_EXTENDED_PRIVATE_KEY[1..]).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(83)")]
        fn from_str_long() {
            let mut string = String::from(VALID_EXTENDED_PRIVATE_KEY);
            string.push('a');
            let _result = BitcoinExtendedPrivateKey::<N>::from_str(&string).unwrap();
        }
    }
}

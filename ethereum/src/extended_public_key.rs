use crate::address::EthereumAddress;
use crate::derivation_path::EthereumDerivationPath;
use crate::extended_private_key::EthereumExtendedPrivateKey;
use crate::format::EthereumFormat;
use crate::network::EthereumNetwork;
use crate::public_key::EthereumPublicKey;
use wagyu_model::{
    crypto::{checksum, hash160},
    AddressError, ChildIndex, DerivationPath, ExtendedPrivateKey, ExtendedPublicKey, ExtendedPublicKeyError, PublicKey,
};

use base58::{FromBase58, ToBase58};
use hex;
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey as Secp256k1_PublicKey, SecretKey};
use sha2::Sha512;
use std::{convert::TryFrom, fmt, marker::PhantomData, str::FromStr};

type HmacSha512 = Hmac<Sha512>;

/// Represents a Ethereum extended public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumExtendedPublicKey<N: EthereumNetwork> {
    /// The depth of key derivation, e.g. 0x00 for master nodes, 0x01 for level-1 derived keys, ...
    depth: u8,
    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    parent_fingerprint: [u8; 4],
    /// The child index of the key (0 for master key)
    child_index: ChildIndex,
    /// The chain code from the extended private key
    chain_code: [u8; 32],
    /// The Ethereum public key
    public_key: EthereumPublicKey,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: EthereumNetwork> ExtendedPublicKey for EthereumExtendedPublicKey<N> {
    type Address = EthereumAddress;
    type DerivationPath = EthereumDerivationPath<N>;
    type ExtendedPrivateKey = EthereumExtendedPrivateKey<N>;
    type Format = EthereumFormat;
    type PublicKey = EthereumPublicKey;

    /// Returns the extended public key of the corresponding extended private key.
    fn from_extended_private_key(extended_private_key: &Self::ExtendedPrivateKey) -> Self {
        Self {
            depth: extended_private_key.depth,
            parent_fingerprint: extended_private_key.parent_fingerprint,
            child_index: extended_private_key.child_index,
            chain_code: extended_private_key.chain_code,
            public_key: extended_private_key.to_public_key(),
            _network: PhantomData,
        }
    }

    /// Returns the extended public key for the given derivation path.
    fn derive(&self, path: &Self::DerivationPath) -> Result<Self, ExtendedPublicKeyError> {
        if self.depth == 255 {
            return Err(ExtendedPublicKeyError::MaximumChildDepthReached(self.depth));
        }

        let mut extended_public_key = self.clone();

        for index in path.to_vec()?.into_iter() {
            let public_key_serialized = &self.public_key.to_secp256k1_public_key().serialize()[..];

            let mut mac = HmacSha512::new_varkey(&self.chain_code)?;
            match index {
                // HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))
                ChildIndex::Normal(_) => mac.input(public_key_serialized),
                // Return failure
                ChildIndex::Hardened(_) => {
                    return Err(ExtendedPublicKeyError::InvalidChildNumber(1 << 31, u32::from(index)))
                }
            }
            // Append the child index in big-endian format
            mac.input(&u32::from(index).to_be_bytes());
            let hmac = mac.result().code();

            let mut chain_code = [0u8; 32];
            chain_code[0..32].copy_from_slice(&hmac[32..]);

            let mut public_key = self.public_key.to_secp256k1_public_key();
            public_key.tweak_add_assign(&SecretKey::parse_slice(&hmac[..32])?)?;
            let public_key = Self::PublicKey::from_secp256k1_public_key(public_key);

            let mut parent_fingerprint = [0u8; 4];
            parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

            extended_public_key = Self {
                depth: extended_public_key.depth + 1,
                parent_fingerprint,
                child_index: index,
                chain_code,
                public_key,
                _network: PhantomData,
            };
        }

        Ok(extended_public_key)
    }

    /// Returns the public key of the corresponding extended public key.
    fn to_public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    /// Returns the address of the corresponding extended public key.
    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        self.public_key.to_address(_format)
    }
}

impl<N: EthereumNetwork> FromStr for EthereumExtendedPublicKey<N> {
    type Err = ExtendedPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58()?;
        if data.len() != 82 {
            return Err(ExtendedPublicKeyError::InvalidByteLength(data.len()));
        }

        if &data[0..4] != [0x04u8, 0x88, 0xB2, 0x1E] {
            return Err(ExtendedPublicKeyError::InvalidVersionBytes(data[0..4].to_vec()));
        };

        let depth = data[4] as u8;

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_index = ChildIndex::from(u32::from_be_bytes(<[u8; 4]>::try_from(&data[9..13])?));

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let public_key = EthereumPublicKey::from_str(&hex::encode(
            &Secp256k1_PublicKey::parse_slice(&data[45..78], None)?.serialize()[1..],
        ))?;

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(ExtendedPublicKeyError::InvalidChecksum(expected, found));
        }

        Ok(Self {
            depth,
            parent_fingerprint,
            child_index,
            chain_code,
            public_key,
            _network: PhantomData,
        })
    }
}

impl<N: EthereumNetwork> fmt::Display for EthereumExtendedPublicKey<N> {
    /// BIP32 serialization format
    /// https://github.com/ethereum/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(&[0x04u8, 0x88, 0xB2, 0x1E][..]);
        result[4] = self.depth as u8;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        result[9..13].copy_from_slice(&u32::from(self.child_index).to_be_bytes());
        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45..78].copy_from_slice(&self.public_key.to_secp256k1_public_key().serialize_compressed());

        let sum = &checksum(&result[0..78])[0..4];
        result[78..82].copy_from_slice(sum);

        fmt.write_str(&result.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;
    use wagyu_model::extended_private_key::ExtendedPrivateKey;

    use hex;
    use std::convert::TryInto;

    fn test_from_extended_private_key<N: EthereumNetwork>(
        expected_extended_public_key: &str,
        expected_public_key: &str,
        expected_child_index: u32,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        extended_private_key: &str,
    ) {
        let extended_private_key = EthereumExtendedPrivateKey::<N>::from_str(extended_private_key).unwrap();
        let extended_public_key = EthereumExtendedPublicKey::<N>::from_extended_private_key(&extended_private_key);
        assert_eq!(expected_extended_public_key, extended_public_key.to_string());
        assert_eq!(
            secp256k1::PublicKey::parse_slice(&hex::decode(expected_public_key).unwrap(), None).unwrap(),
            extended_public_key.public_key.to_secp256k1_public_key()
        );
        assert_eq!(expected_child_index, u32::from(extended_public_key.child_index));
        assert_eq!(expected_chain_code, hex::encode(extended_public_key.chain_code));
        assert_eq!(
            expected_parent_fingerprint,
            hex::encode(extended_public_key.parent_fingerprint)
        );
    }

    // Check: (extended_private_key1 -> extended_private_key2 -> extended_public_key2) == (expected_extended_public_key2)
    fn test_derive<N: EthereumNetwork>(
        expected_extended_private_key1: &str,
        expected_extended_public_key2: &str,
        expected_child_index2: u32,
    ) {
        let path = vec![ChildIndex::from(expected_child_index2)].try_into().unwrap();

        let extended_private_key1 = EthereumExtendedPrivateKey::<N>::from_str(expected_extended_private_key1).unwrap();
        let extended_private_key2 = extended_private_key1.derive(&path).unwrap();
        let extended_public_key2 = extended_private_key2.to_extended_public_key();

        let expected_extended_public_key2 =
            EthereumExtendedPublicKey::<N>::from_str(&expected_extended_public_key2).unwrap();

        assert_eq!(expected_extended_public_key2, extended_public_key2);
        assert_eq!(
            expected_extended_public_key2.public_key,
            extended_public_key2.public_key
        );
        assert_eq!(expected_extended_public_key2.depth, extended_public_key2.depth);
        assert_eq!(
            expected_extended_public_key2.child_index,
            extended_public_key2.child_index
        );
        assert_eq!(
            expected_extended_public_key2.chain_code,
            extended_public_key2.chain_code
        );
        assert_eq!(
            expected_extended_public_key2.parent_fingerprint,
            extended_public_key2.parent_fingerprint
        );
    }

    fn test_from_str<N: EthereumNetwork>(
        expected_public_key: &str,
        expected_child_index: u32,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        extended_public_key: &str,
    ) {
        let extended_public_key = EthereumExtendedPublicKey::<N>::from_str(&extended_public_key).unwrap();
        assert_eq!(
            secp256k1::PublicKey::parse_slice(&hex::decode(expected_public_key).unwrap(), None).unwrap(),
            extended_public_key.public_key.to_secp256k1_public_key()
        );
        assert_eq!(expected_child_index, u32::from(extended_public_key.child_index));
        assert_eq!(expected_chain_code, hex::encode(extended_public_key.chain_code));
        assert_eq!(
            expected_parent_fingerprint,
            hex::encode(extended_public_key.parent_fingerprint)
        );
    }

    fn test_to_string<N: EthereumNetwork>(expected_extended_public_key: &str) {
        let extended_public_key = EthereumExtendedPublicKey::<N>::from_str(&expected_extended_public_key).unwrap();
        assert_eq!(expected_extended_public_key, extended_public_key.to_string());
    }

    mod bip32_mainnet {
        use super::*;

        type N = Mainnet;

        // (path, seed, child_index, public_key, chain_code, parent_fingerprint, extended_private_key, extended_public_key)
        const KEYPAIRS: [(&str, &str, &str, &str, &str, &str, &str, &str); 12] = [
            (
                "m",
                "000102030405060708090a0b0c0d0e0f",
                "0",
                "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
                "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                "00000000",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
            ),
            (
                "m/0'",
                "000102030405060708090a0b0c0d0e0f",
                "2147483648",
                "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
                "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                "3442193e",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
            ),
            (
                "m/0'/1",
                "000102030405060708090a0b0c0d0e0f",
                "1",
                "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
                "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
                "5c1bd648",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
            ),
            (
                "m/0'/1/2'",
                "000102030405060708090a0b0c0d0e0f",
                "2147483650",
                "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
                "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
                "bef5a2f9",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
            ),
            (
                "m/0'/1/2'/2",
                "000102030405060708090a0b0c0d0e0f",
                "2",
                "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
                "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
                "ee7ab90c",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
            ),
            (
                "m/0'/1/2'/2/1000000000",
                "000102030405060708090a0b0c0d0e0f",
                "1000000000",
                "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
                "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
                "d880d7d8",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
            ),
            (
                "m",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "0",
                "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
                "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                "00000000",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
            ),
            (
                "m/0",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "0",
                "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
                "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                "bd16bee5",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
            ),
            (
                "m/0/2147483647'",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "4294967295",
                "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
                "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
                "5a61ff8e",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
            ),
            (
                "m/0/2147483647'/1",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "1",
                "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
                "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
                "d8ab4937",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "4294967294",
                "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
                "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
                "78412e3a",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "2",
                "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
                "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
                "31a507b8",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
            ),
        ];

        #[test]
        fn from_extended_private_key() {
            KEYPAIRS.iter().for_each(
                |(
                    _,
                    _,
                    child_index,
                    public_key,
                    chain_code,
                    parent_fingerprint,
                    extended_private_key,
                    extended_public_key,
                )| {
                    test_from_extended_private_key::<N>(
                        extended_public_key,
                        public_key,
                        child_index.parse().unwrap(),
                        chain_code,
                        parent_fingerprint,
                        extended_private_key,
                    );
                },
            );
        }

        #[test]
        fn derive() {
            KEYPAIRS.chunks(2).for_each(|pair| {
                let (_, _, _, _, _, _, expected_extended_private_key1, _) = pair[0];
                let (_, _, expected_child_index2, _, _, _, _, expected_extended_public_key2) = pair[1];
                test_derive::<N>(
                    expected_extended_private_key1,
                    expected_extended_public_key2,
                    expected_child_index2.parse().unwrap(),
                );
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(
                |(_, _, child_index, public_key, chain_code, parent_fingerprint, _, extended_public_key)| {
                    test_from_str::<N>(
                        public_key,
                        child_index.parse().unwrap(),
                        chain_code,
                        parent_fingerprint,
                        extended_public_key,
                    );
                },
            );
        }

        #[test]
        fn to_string() {
            KEYPAIRS.iter().for_each(|(_, _, _, _, _, _, _, extended_public_key)| {
                test_to_string::<N>(extended_public_key);
            });
        }
    }

    mod test_invalid {
        use super::*;

        type N = Mainnet;

        const INVALID_EXTENDED_PUBLIC_KEY__SECP256K1_PUBLIC_KEY: &str = "xpub661MyMwAqRbcftXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        const INVALID_EXTENDED_PUBLIC_KEY_NETWORK: &str = "xpub561MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        const INVALID_EXTENDED_PUBLIC_KEY_CHECKSUM: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet7";
        const VALID_EXTENDED_PUBLIC_KEY: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        #[test]
        #[should_panic(expected = "Crate(\"libsecp256k1\", \"InvalidPublicKey\")")]
        fn from_str_invalid_secret_key() {
            let _result =
                EthereumExtendedPublicKey::<N>::from_str(INVALID_EXTENDED_PUBLIC_KEY__SECP256K1_PUBLIC_KEY).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidVersionBytes([4, 136, 178, 29])")]
        fn from_str_invalid_version() {
            let _result = EthereumExtendedPublicKey::<N>::from_str(INVALID_EXTENDED_PUBLIC_KEY_NETWORK).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidChecksum(\"5Nvot3\", \"5Nvot4\")")]
        fn from_str_invalid_checksum() {
            let _result = EthereumExtendedPublicKey::<N>::from_str(INVALID_EXTENDED_PUBLIC_KEY_CHECKSUM).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(81)")]
        fn from_str_short() {
            let _result = EthereumExtendedPublicKey::<N>::from_str(&VALID_EXTENDED_PUBLIC_KEY[1..]).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(83)")]
        fn from_str_long() {
            let mut string = String::from(VALID_EXTENDED_PUBLIC_KEY);
            string.push('a');
            let _result = EthereumExtendedPublicKey::<N>::from_str(&string).unwrap();
        }
    }
}

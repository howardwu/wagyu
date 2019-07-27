use crate::address::EthereumAddress;
use crate::derivation_path::{ChildIndex, EthereumDerivationPath};
use crate::extended_private_key::EthereumExtendedPrivateKey;
use crate::public_key::EthereumPublicKey;
use wagu_model::{
    AddressError,
    ExtendedPublicKey,
    ExtendedPublicKeyError,
    PublicKey,
    crypto::{checksum, hash160}};

use base58::{ToBase58, FromBase58};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use hex;
use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey, PublicKey as Secp256k1_PublicKey};
use sha2::Sha512;
use std::fmt;
use std::io::Cursor;
use std::str::FromStr;
use serde::export::PhantomData;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Ethereum extended public key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EthereumExtendedPublicKey {
    /// The depth of key derivation, e.g. 0x00 for master nodes, 0x01 for level-1 derived keys, ...
    pub depth: u8,
    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    pub parent_fingerprint: [u8; 4],
    /// The child index of the key (0 for master key)
    pub child_index: ChildIndex,
    /// The chain code from the extended private key
    pub chain_code: [u8; 32],
    /// The Ethereum public key
    pub public_key: EthereumPublicKey,
}

impl ExtendedPublicKey for EthereumExtendedPublicKey {
    type Address = EthereumAddress;
    type DerivationPath = EthereumDerivationPath;
    type ExtendedPrivateKey = EthereumExtendedPrivateKey;
    type Format = PhantomData<u8>;
    type PublicKey = EthereumPublicKey;

    /// Returns the extended public key of the corresponding extended private key.
    fn from_extended_private_key(extended_private_key: &Self::ExtendedPrivateKey) -> Self {
        Self {
            depth: extended_private_key.depth,
            parent_fingerprint: extended_private_key.parent_fingerprint,
            child_index: extended_private_key.child_index,
            chain_code: extended_private_key.chain_code,
            public_key: Self::PublicKey::from_private_key(&extended_private_key.private_key),
        }
    }

    /// Returns the extended public key for the given derivation path.
    fn derive(&self, path: &Self::DerivationPath) -> Result<Self, ExtendedPublicKeyError> {
        if self.depth == 255 {
            return Err(ExtendedPublicKeyError::MaximumChildDepthReached(self.depth))
        }

        let mut extended_public_key = self.clone();

        for index in path.0.iter() {
            let public_key_serialized = &self.public_key.0.serialize()[..];

            let mut mac = HmacSha512::new_varkey(&self.chain_code)?;
            match index {
                // HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))
                ChildIndex::Normal(_) => mac.input(public_key_serialized),
                // Return failure
                ChildIndex::Hardened(_) => return Err(ExtendedPublicKeyError::InvalidChildNumber(1 << 31, u32::from(*index)))
            }
            let mut index_be = [0; 4];
            BigEndian::write_u32(&mut index_be, u32::from(*index));
            mac.input(&index_be);
            let hmac = mac.result().code();

            let mut chain_code = [0u8; 32];
            chain_code[0..32].copy_from_slice(&hmac[32..]);

            let mut public_key = self.public_key;
            public_key.0.add_exp_assign(&Secp256k1::new(), &SecretKey::from_slice( &hmac[..32])?[..])?;

            let mut parent_fingerprint = [0u8; 4];
            parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

            extended_public_key = Self {
                depth: self.depth + 1,
                parent_fingerprint,
                child_index: *index,
                chain_code,
                public_key,
            };
        }

        Ok(extended_public_key)
    }

    /// Returns the public key of the corresponding extended public key.
    fn to_public_key(&self) -> Self::PublicKey {
        self.public_key
    }

    /// Returns the address of the corresponding extended public key.
    fn to_address(&self, _: &Self::Format) -> Result<Self::Address, AddressError> {
        self.public_key.to_address(&PhantomData)
    }
}

impl FromStr for EthereumExtendedPublicKey {
    type Err = ExtendedPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58()?;
        if data.len() != 82 {
            return Err(ExtendedPublicKeyError::InvalidByteLength(data.len()))
        }

        if &data[0..4] != [0x04u8, 0x88, 0xB2, 0x1E] {
            return Err(ExtendedPublicKeyError::InvalidVersionBytes(data[0..4].to_vec()))
        };

        let depth = data[4] as u8;

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_index = ChildIndex::from(Cursor::new(&data[9..13]).read_u32::<BigEndian>()?);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let public_key = EthereumPublicKey::from_str(
            &hex::encode(&Secp256k1_PublicKey::from_slice(&data[45..78])?.serialize_uncompressed()[1..]))?;

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(ExtendedPublicKeyError::InvalidChecksum(expected, found))
        }

        Ok(Self {
            depth,
            parent_fingerprint,
            child_index,
            chain_code,
            public_key,
        })
    }
}

impl fmt::Display for EthereumExtendedPublicKey {
    /// BIP32 serialization format
    /// https://github.com/ethereum/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(&[0x04u8, 0x88, 0xB2, 0x1E][..]);
        result[4] = self.depth as u8;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        BigEndian::write_u32(&mut result[9..13], u32::from(self.child_index));

        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45..78].copy_from_slice(&self.public_key.0.serialize()[..]);

        let sum = &checksum(&result[0..78])[0..4];
        result[78..82].copy_from_slice(sum);

        fmt.write_str(&result.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn test_from_str(
        expected_public_key: &str,
        expected_chain_code: &str,
        expected_depth: u8,
        expected_parent_fingerprint: &str,
        expected_child_number: u32,
        expected_xpub_serialized: &str,
    ) {
        let xpub = EthereumExtendedPublicKey::from_str(&expected_xpub_serialized).expect("Error generating xpub from string");
        assert_eq!(expected_public_key, xpub.public_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(xpub.chain_code));
        assert_eq!(expected_depth, xpub.depth);
        assert_eq!(expected_parent_fingerprint, hex::encode(xpub.parent_fingerprint));
        assert_eq!(expected_child_number, u32::from(xpub.child_index));
        assert_eq!(expected_xpub_serialized, xpub.to_string());
    }

    fn test_from_private(
        expected_public_key: &str,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        expected_xpub_serialized: &str,
        xpriv_serialized: &str,
    ) {
        let xpriv = EthereumExtendedPrivateKey::from_str(xpriv_serialized).unwrap();
        let xpub = EthereumExtendedPublicKey::from_extended_private_key(&xpriv);
        assert_eq!(expected_public_key, xpub.public_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(xpub.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(xpub.parent_fingerprint));
        assert_eq!(expected_xpub_serialized, xpub.to_string());
    }

    mod bip32_default {
        use super::*;
        use wagu_model::ExtendedPrivateKey;

        // (depth, master_seed, public_key, chain_code, parent_fingerprint, xpriv_serialized, xpub_serialized)
        const KEYPAIR_TREE_HARDENED: [(&str, &str, &str, &str, &str, &str, &str); 2] = [
            (
                "0x00",
                "000102030405060708090a0b0c0d0e0f",
                "39a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281",
                "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                "00000000",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
            ),
            (
                "0x01",
                "m/0'",
                "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
                "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                "3442193e",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
            )
        ];

        // (depth, master_seed, secret_key, chain_code, parent_fingerprint, xpriv_serialized, xpub_serialized)
        const KEYPAIR_TREE_NORMAL: [(&str, &str, &str, &str, &str, &str, &str); 2] = [
            (
                "0x00",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a77bd3305d363c26f82c1e41c667e4b3561c06c60a2104d2b548e6dd059056aa51",
                "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                "00000000",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
            ),
            (
                "0x01",
                "m/0",
                "fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea67a50538b6f7d8b5f7a1cc657efd267cde8cc1d8c0451d1340a0fb3642777544",
                "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                "bd16bee5",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
            )
        ];

        #[test]
        fn test_from_str_hardened() {
            let (
                _,
                _,
                public_key,
                chain_code,
                parent_fingerprint,
                _,
                xpub
            ) = KEYPAIR_TREE_HARDENED[0];
            test_from_str(
                public_key,
                chain_code,
                0,
                parent_fingerprint,
                0,
                xpub,
            );
        }

        #[test]
        fn test_from_str_normal() {
            let (
                _,
                _,
                public_key,
                chain_code,
                parent_fingerprint,
                _,
                xpub
            ) = KEYPAIR_TREE_NORMAL[0];
            test_from_str(
                public_key,
                chain_code,
                0,
                parent_fingerprint,
                0,
                xpub,
            );
        }

        #[test]
        fn test_from_private_hardened() {
            let (
                _,
                _,
                public_key,
                chain_code,
                parent_fingerprint,
                xpriv,
                xpub
            ) = KEYPAIR_TREE_HARDENED[0];
            test_from_private(
                public_key,
                chain_code,
                parent_fingerprint,
                xpub,
                xpriv,
            );
        }

        #[test]
        fn test_from_private_normal() {
            let (
                _,
                _,
                public_key,
                chain_code,
                parent_fingerprint,
                xpriv,
                xpub
            ) = KEYPAIR_TREE_NORMAL[0];
            test_from_private(
                public_key,
                chain_code,
                parent_fingerprint,
                xpub,
                xpriv,
            );
        }
    }

    mod test_invalid {
        use super::*;

        const INVALID_XPUB_PUBLIC_KEY: &str = "xpub661MyMwAqRbcftXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        const INVALID_XPUB_NETWORK: &str = "xpub561MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        const INVALID_XPUB_CHECKSUM: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet7";
        const VALID_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        #[test]
        #[should_panic(expected = "Crate(\"secp256k1\", \"InvalidPublicKey\")")]
        fn from_str_invalid_secret_key() {
            let _result = EthereumExtendedPublicKey::from_str(INVALID_XPUB_PUBLIC_KEY).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidVersionBytes([4, 136, 178, 29])")]
        fn from_str_invalid_version() {
            let _result = EthereumExtendedPublicKey::from_str(INVALID_XPUB_NETWORK).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidChecksum(\"5Nvot3\", \"5Nvot4\")")]
        fn from_str_invalid_checksum() {
            let _result = EthereumExtendedPublicKey::from_str(INVALID_XPUB_CHECKSUM).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(81)")]
        fn from_str_short() {
            let _result = EthereumExtendedPublicKey::from_str(&VALID_XPUB[1..]).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(83)")]
        fn from_str_long() {
            let mut string = String::from(VALID_XPUB);
            string.push('a');
            let _result = EthereumExtendedPublicKey::from_str(&string).unwrap();
        }
    }
}
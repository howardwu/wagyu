use crate::address::{BitcoinAddress, Format};
use crate::extended_private_key::BitcoinExtendedPrivateKey;
use crate::network::BitcoinNetwork;
use crate::public_key::BitcoinPublicKey;
use wagu_model::{
    AddressError,
    ExtendedPublicKey,
    ExtendedPublicKeyError,
    PublicKey,
    crypto::{checksum, hash160}
};

use base58::{ToBase58, FromBase58};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey, PublicKey as Secp256k1_PublicKey};
use sha2::Sha512;
use std::fmt;
use std::io::Cursor;
use std::str::FromStr;
use std::ops::AddAssign;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Bitcoin extended public key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitcoinExtendedPublicKey {
    /// The Bitcoin public key
    pub public_key: BitcoinPublicKey,
    /// The chain code from the extended private key
    pub chain_code: [u8; 32],
    /// The network of this extended public key
    pub network: BitcoinNetwork,
    /// The depth of key derivation, e.g. 0x00 for master nodes, 0x01 for level-1 derived keys, ...
    pub depth: u8,
    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    pub parent_fingerprint: [u8; 4],
    /// This is ser32(i) for i in x_i = x_par/i, with x_i the key being serialized. (0x00000000 if master key)
    pub child_number: u32,
}

impl ExtendedPublicKey for BitcoinExtendedPublicKey {
    type Address = BitcoinAddress;
    type ExtendedPrivateKey = BitcoinExtendedPrivateKey;
    type Format = Format;
    type Network = BitcoinNetwork;
    type PublicKey = BitcoinPublicKey;

    /// Returns the extended public key of the corresponding extended private key.
    fn from_extended_private_key(private_key: &Self::ExtendedPrivateKey) -> Self {
        Self {
            public_key: BitcoinPublicKey::from_private_key(&private_key.private_key),
            chain_code: private_key.chain_code,
            network: private_key.network,
            depth: private_key.depth,
            parent_fingerprint: private_key.parent_fingerprint,
            child_number: private_key.child_number,
        }
    }

    /// Returns the public key of the corresponding extended public key.
    fn to_public_key(&self) -> Self::PublicKey {
        self.public_key
    }

    /// Returns the address of the corresponding extended public key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        self.public_key.to_address(format, &self.network)
    }
}

impl BitcoinExtendedPublicKey {
    /// Returns the extended public key for the given derivation path.
    pub fn derivation_path(&self, path: &str) -> Result<Self, ExtendedPublicKeyError> {
        let mut path_vec: Vec<&str> = path.split("/").collect();

        if path_vec[0] != "m" {
            return Err(ExtendedPublicKeyError::InvalidDerivationPath("m".into(), path_vec[0].into()))
        }

        if path_vec.len() == 1 {
            return Ok(self.clone())
        }

        let mut xpub = self.clone();
        for (i, child_str) in path_vec[1..].iter_mut().enumerate() {
            let mut child_num = 0u32;

            // if hardened path return failure
            if child_str.contains("'") {
                return Err(ExtendedPublicKeyError::InvalidDerivationPath("".into(), "'".into()))
            } else {
                let child_num_u32: u32 = match child_str.parse() {
                    Ok(num) => num,
                    Err(_) => return Err(ExtendedPublicKeyError::InvalidDerivationPath("number".into(), path_vec[i + 1].into()))
                };
                child_num.add_assign(child_num_u32);
            }
            xpub = xpub.ckd_pub(child_num)?;
        }

        Ok(xpub)
    }

    /// Returns the child extended public key for the given child number.
    pub fn ckd_pub(&self, child_number: u32) -> Result<Self, ExtendedPublicKeyError> {
        if self.depth == 255 {
            return Err(ExtendedPublicKeyError::MaximumChildDepthReached(self.depth))
        }

        let mut mac = HmacSha512::new_varkey(&self.chain_code)?;
        let public_key_serialized = &self.public_key.public_key.serialize()[..];

        // Check whether i ≥ 2^31 (whether the child is a hardened key).
        //
        // If so (hardened child): return failure
        // If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
        //
        if child_number >= 2_u32.pow(31) {
            return Err(ExtendedPublicKeyError::InvalidChildNumber(2_u32.pow(31), child_number))
        } else {
            mac.input(public_key_serialized);
        }

        let mut child_num_big_endian = [0; 4];
        BigEndian::write_u32(&mut child_num_big_endian, child_number);
        mac.input(&child_num_big_endian);

        let result = mac.result().code();

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);

        let secret_key = SecretKey::from_slice(&Secp256k1::without_caps(), &result[..32])?;
        let mut public_key = self.public_key.clone();
        public_key.public_key.add_exp_assign(&Secp256k1::new(), &secret_key)?;

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

        Ok(Self {
            public_key,
            chain_code,
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,
        })
    }
}

impl FromStr for BitcoinExtendedPublicKey {
    type Err = ExtendedPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58()?;
        if data.len() != 82 {
            return Err(ExtendedPublicKeyError::InvalidByteLength(data.len()))
        }

        // TODO (howardwu): Move this to network.rs
        let network = if &data[0..4] == [0x04u8, 0x88, 0xB2, 0x1E] {
            BitcoinNetwork::Mainnet
        } else if &data[0..4] == [0x04u8, 0x35, 0x87, 0xCF] {
            BitcoinNetwork::Testnet
        } else {
            return Err(ExtendedPublicKeyError::InvalidNetworkBytes(data[0..4].to_vec()))
        };

        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_number: u32 = Cursor::new(&data[9..13]).read_u32::<BigEndian>()?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let secp = Secp256k1::new();
        let secp256k1_public_key = Secp256k1_PublicKey::from_slice(&secp,&data[45..78])?;
        let public_key = BitcoinPublicKey::from_str(&secp256k1_public_key.to_string())?;

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(ExtendedPublicKeyError::InvalidChecksum(expected, found))
        }

        Ok(Self {
            public_key,
            chain_code,
            network,
            depth,
            parent_fingerprint,
            child_number
        })
    }
}

impl fmt::Display for BitcoinExtendedPublicKey {
    /// BIP32 serialization format
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(&match self.network {
            BitcoinNetwork::Mainnet => [0x04u8, 0x88, 0xB2, 0x1E],
            BitcoinNetwork::Testnet => [0x04u8, 0x35, 0x87, 0xCF],
        }[..]);
        result[4] = self.depth;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        BigEndian::write_u32(&mut result[9..13], u32::from(self.child_number));

        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45..78].copy_from_slice(&self.public_key.public_key.serialize()[..]);

        let sum = &checksum(&result[0..78])[0..4];
        result[78..82].copy_from_slice(sum);

        fmt.write_str(&result.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wagu_model::ExtendedPrivateKey;
    use hex;

    fn test_from_str(
        expected_public_key: &str,
        expected_chain_code: &str,
        expected_depth: u8,
        expected_parent_fingerprint: &str,
        expected_child_number: u32,
        expected_xpub_serialized: &str
    ) {
        let xpub = BitcoinExtendedPublicKey::from_str(&expected_xpub_serialized).unwrap();
        assert_eq!(expected_public_key, xpub.public_key.public_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(xpub.chain_code));
        assert_eq!(expected_depth, xpub.depth);
        assert_eq!(expected_parent_fingerprint, hex::encode(xpub.parent_fingerprint));
        assert_eq!(expected_child_number, xpub.child_number);
        assert_eq!(expected_xpub_serialized, xpub.to_string());
    }

    fn test_from_private(
        expected_public_key: &str,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        expected_xpub_serialized: &str,
        xpriv_serialized: &str
    ) {
        let xpriv = BitcoinExtendedPrivateKey::from_str(xpriv_serialized).unwrap();
        let xpub = BitcoinExtendedPublicKey::from_extended_private_key(&xpriv);
        assert_eq!(expected_public_key, xpub.public_key.public_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(xpub.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(xpub.parent_fingerprint));
        assert_eq!(expected_xpub_serialized, xpub.to_string());
    }

    fn test_ckd_pub(
        expected_public_key: &str,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        expected_xpub_serialized: &str,
        parent_xpub: &BitcoinExtendedPublicKey,
        child_number: u32,
    ) -> BitcoinExtendedPublicKey {
        let child_xpub = parent_xpub.ckd_pub(child_number).unwrap();
        assert_eq!(expected_public_key, child_xpub.public_key.public_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(child_xpub.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(child_xpub.parent_fingerprint));
        assert_eq!(expected_xpub_serialized, child_xpub.to_string());
        assert_eq!(child_number, child_xpub.child_number);

        child_xpub
    }

    fn test_derivation_path(
        expected_public_key: &str,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        expected_xpub_serialized: &str,
        parent_xpub: &BitcoinExtendedPublicKey,
        path: &str,
    ) {
        let derived_xpub = parent_xpub.derivation_path(path).unwrap();
        assert_eq!(expected_public_key, derived_xpub.public_key.public_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(derived_xpub.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(derived_xpub.parent_fingerprint));
        assert_eq!(expected_xpub_serialized, derived_xpub.to_string());
    }

    mod bip32_default {
        use super::*;

        // (depth, master_seed, public_key, chain_code, parent_fingerprint, xpriv_serialized, xpub_serialized)
        const KEYPAIR_TREE_HARDENED: [(&str, &str, &str, &str, &str, &str, &str); 2] = [
            (
                "0x00",
                "000102030405060708090a0b0c0d0e0f",
                "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
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
                "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
                "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                "00000000",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
            ),
            (
                "0x01",
                "m/0",
                "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
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
                xpub
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
                xpub
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
                xpriv
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
                xpriv
            );
        }

        #[test]
        fn test_ckd_pub_normal() {
            let (_, _, _, _, _, xpriv_serialized, _) = KEYPAIR_TREE_NORMAL[0];
            let parent_xpriv = BitcoinExtendedPrivateKey::from_str(xpriv_serialized).unwrap();
            let mut parent_xpub = parent_xpriv.to_extended_public_key();
            for (i,
                (
                    _,
                    _,
                    public_key,
                    chain_code,
                    parent_fingerprint,
                    _,
                    xpub
                )
            ) in KEYPAIR_TREE_NORMAL[1..].iter_mut().enumerate() {
                parent_xpub = test_ckd_pub(
                    public_key,
                    chain_code,
                    parent_fingerprint,
                    xpub,
                    &parent_xpub,
                    i as u32,
                );
            }
        }

        #[test]
        #[should_panic(expected = "InvalidChildNumber(2147483648, 2147483648)")]
        fn test_ckd_pub_hardened_panic() {
            let (_, _, _, _, _, xpriv_serialized, _) = KEYPAIR_TREE_HARDENED[0];
            let parent_xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            let parent_xpub = parent_xpriv.to_extended_public_key();
            let _result = parent_xpub.ckd_pub(2_u32.pow(31)).unwrap();
        }

        #[test]
        fn test_derivation_path_normal() {
            let (_, _, _, _, _, xpriv_serialized, _) = KEYPAIR_TREE_NORMAL[0];
            let parent_xpriv = BitcoinExtendedPrivateKey::from_str(xpriv_serialized).unwrap();
            let parent_xpub = parent_xpriv.to_extended_public_key();
            for (_,
                (
                    _,
                    path,
                    public_key,
                    chain_code,
                    parent_fingerprint,
                    _,
                    xpub
                )
            ) in KEYPAIR_TREE_NORMAL[1..].iter_mut().enumerate() {
                test_derivation_path(
                    public_key,
                    chain_code,
                    parent_fingerprint,
                    xpub,
                    &parent_xpub,
                    path,
                );
            }
        }

        #[test]
        #[should_panic(expected = "InvalidDerivationPath(\"\", \"\\'\")")]
        fn test_derivation_path_hardened_panic() {
            let (_, _, _, _, _, xpriv_serialized, _) = KEYPAIR_TREE_HARDENED[0];
            let parent_xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            let parent_xpub = parent_xpriv.to_extended_public_key();
            let _result = parent_xpub.derivation_path("m/0'").unwrap();
        }
    }

    mod test_invalid {
        use super::*;

        const INVALID_PATH: &str = "/0";
        const INVALID_PATH_HARDENED: &str = "m/a'";
        const INVALID_PATH_NORMAL: &str = "m/a";
        const INVALID_XPUB_PUBLIC_KEY: &str = "xpub661MyMwAqRbcftXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        const INVALID_XPUB_NETWORK: &str = "xpub561MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        const INVALID_XPUB_CHECKSUM: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet7";
        const VALID_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        const VALID_XPUB_FINAL: &str = "xpubEND4cWBkwMUcwj3bjw4RNYcpnuvgbEaGSCAujB1XQro3Ptpvs8hDMFsBmk1mhfz9sGc3k4XPpueGAcR66Kb7HMXwfnKKBaV3i7YyMxLuwKh";

        #[test]
        #[should_panic(expected = "Crate(\"secp256k1\", \"InvalidPublicKey\")")]
        fn from_str_invalid_secret_key() {
            let _result = BitcoinExtendedPublicKey::from_str(INVALID_XPUB_PUBLIC_KEY).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidNetworkBytes([4, 136, 178, 29])")]
        fn from_str_invalid_network() {
            let _result = BitcoinExtendedPublicKey::from_str(INVALID_XPUB_NETWORK).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidChecksum(\"5Nvot3\", \"5Nvot4\")")]
        fn from_str_invalid_checksum() {
            let _result = BitcoinExtendedPublicKey::from_str(INVALID_XPUB_CHECKSUM).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(81)")]
        fn from_str_short() {
            let _result = BitcoinExtendedPublicKey::from_str(&VALID_XPUB[1..]).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(83)")]
        fn from_str_long() {
            let mut string = String::from(VALID_XPUB);
            string.push('a');
            let _result = BitcoinExtendedPublicKey::from_str(&string).unwrap();
        }

        #[test]
        #[should_panic(expected = "MaximumChildDepthReached(255)")]
        fn ckd_pub_max_depth() {
            let mut xpub = BitcoinExtendedPublicKey::from_str(VALID_XPUB).unwrap();
            for _ in 0..255 {
                xpub = xpub.ckd_pub(0).unwrap();
            }
            assert_eq!(xpub.to_string(), VALID_XPUB_FINAL);
            let _result = xpub.ckd_pub(0).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidDerivationPath(\"m\", \"\")")]
        fn derivation_path_invalid() {
            let xpub = BitcoinExtendedPublicKey::from_str(VALID_XPUB).unwrap();
            let _result = xpub.derivation_path(INVALID_PATH).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidDerivationPath(\"number\", \"a\")")]
        fn derivation_path_invalid_digit_normal() {
            let xpub = BitcoinExtendedPublicKey::from_str(VALID_XPUB).unwrap();
            let _result = xpub.derivation_path(INVALID_PATH_NORMAL).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidDerivationPath(\"\", \"\\'\")")]
        fn derivation_path_invalid_digit_hardened() {
            let xpub = BitcoinExtendedPublicKey::from_str(VALID_XPUB).unwrap();
            let _result = xpub.derivation_path(INVALID_PATH_HARDENED).unwrap();
        }
    }
}
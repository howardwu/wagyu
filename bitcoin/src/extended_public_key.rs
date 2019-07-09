use model::{PublicKey, crypto::{checksum, hash160}};
use crate::public_key::BitcoinPublicKey;
use crate::extended_private_key::BitcoinExtendedPrivateKey;
use crate::network::Network;

use base58::{ToBase58, FromBase58};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey, PublicKey as Secp256k1_PublicKey};
use sha2::Sha512;

use std::fmt;
use std::io::Cursor;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Bitcoin extended public key
pub struct BitcoinExtendedPublicKey {
    /// The Secp256k1 public key associated with a BitcoinExtendedPrivateKey's private_key
    pub public_key: BitcoinPublicKey,

    /// The chain code associated with a BitcoinExtendedPrivateKey
    pub chain_code: [u8; 32],

    /// the network this extended public key can be used on
    pub network: Network,

    /// 0x00 for master nodes, 0x01 for level-1 derived keys, ....
    pub depth: u8,

    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    pub parent_fingerprint: [u8; 4],

    /// This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    pub child_number: u32,
}

impl BitcoinExtendedPublicKey {
    /// Returns extended public key given extended private key
    pub fn from_private(private_key: &BitcoinExtendedPrivateKey) -> Self {
        Self {
            public_key: BitcoinPublicKey::from_private_key(&private_key.private_key),
            chain_code: private_key.chain_code,
            network: private_key.network,
            depth: private_key.depth,
            parent_fingerprint: private_key.parent_fingerprint,
            child_number: private_key.child_number,
        }
    }

    /// Generates a child extended public key at child_number from the current extended private key
    pub fn ckd_pub(&self, child_number: u32) -> Self {

        let mut mac = HmacSha512::new_varkey(
            &self.chain_code).expect("error generating hmac");
        let public_key_serialized = &self.public_key.public_key.serialize()[..];

        // Check whether i ≥ 231 (whether the child is a hardened key).
        // If so (hardened child): return failure
        // If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
        if child_number >= 2_u32.pow(31) {
            panic!("Cannot derive hardened child from extended public key")
        } else {
            mac.input(public_key_serialized);
        }

        let mut child_num_big_endian = [0; 4];
        BigEndian::write_u32(&mut child_num_big_endian, child_number);
        mac.input(&child_num_big_endian);

        let result = mac.result().code();

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);

        let secret_key = SecretKey::from_slice(
            &Secp256k1::without_caps(),
            &result[..32]).expect("error generating secret key");
        let mut public_key = self.public_key.clone();
        public_key.public_key.add_exp_assign(&Secp256k1::new(), &secret_key).expect("error exp assign");

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

        Self {
            public_key,
            chain_code,
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,
        }
    }
}

impl FromStr for BitcoinExtendedPublicKey {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, &'static str> {
        let data = s.from_base58().expect("Error decoding base58 extended publicd key string");
        if data.len() != 82 {
            return Err("Invalid extended public key length");
        }

        let network = if &data[0..4] == [0x04u8, 0x88, 0xB2, 0x1E] {
            Network::Mainnet
        } else if &data[0..4] == [0x04u8, 0x35, 0x87, 0xCF] {
            Network::Testnet
        } else {
            return Err("Invalid network version");
        };

        let depth = data[4] as u8;

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_number: u32 = Cursor::new(&data[9..13]).read_u32::<BigEndian>().unwrap();

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let secp = Secp256k1::new();
        let secp256k1_public_key = Secp256k1_PublicKey::from_slice(&secp,&data[45..78]).expect("Error deriving secp256k1 public key from slice");;
        let public_key = BitcoinPublicKey::from_str(&secp256k1_public_key.to_string()).expect("Error deriving bitcoin public key");

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];

        match *expected == *checksum {
            true => Ok(Self {
                public_key,
                chain_code,
                network,
                depth,
                parent_fingerprint,
                child_number
            }),
            false => Err("Invalid extended public key")
        }
    }
}

impl fmt::Display for BitcoinExtendedPublicKey {
    /// BIP32 serialization format: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(&match self.network {
            Network::Mainnet => [0x04u8, 0x88, 0xB2, 0x1E],
            Network::Testnet => [0x04u8, 0x35, 0x87, 0xCF],
        }[..]);
        result[4] = self.depth as u8;
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
    use hex;

    fn test_from_str(
        expected_public_key: &str,
        expected_chain_code: &str,
        expected_depth: u8,
        expected_parent_fingerprint: &str,
        expected_child_number: u32,
        expected_xpub_serialized: &str
    ) {
        let xpub = BitcoinExtendedPublicKey::from_str(&expected_xpub_serialized).expect("Error generating xpub from string");
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
        seed: &str
    ) {
        let seed = hex::decode(seed).unwrap();
        let xpriv = BitcoinExtendedPrivateKey::new(&seed);
        let xpub = BitcoinExtendedPublicKey::from_private(&xpriv);
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
        let child_xpub = parent_xpub.ckd_pub(child_number);
        assert_eq!(expected_public_key, child_xpub.public_key.public_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(child_xpub.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(child_xpub.parent_fingerprint));
        assert_eq!(expected_xpub_serialized, child_xpub.to_string());
        assert_eq!(child_number, child_xpub.child_number);

        child_xpub
    }

    mod bip32_default {
        use super::*;

        // (depth, master_seed, public_key, chain_code, parent_fingerprint, xpub_serialized)
        const KEYPAIR_TREE_HARDENED: [(&str, &str, &str, &str, &str, &str); 2] = [
            (
                "0x00",
                "000102030405060708090a0b0c0d0e0f",
                "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
                "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                "00000000",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
            ),
            (
                "0x01",
                "000102030405060708090a0b0c0d0e0f",
                "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
                "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                "0x3442193e",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
            )
        ];

        // (depth, master_seed, secret_key, chain_code, parent_fingerprint, xpub_serialized)
        const KEYPAIR_TREE_NORMAL: [(&str, &str, &str, &str, &str, &str); 2] = [
            (
                "0x00",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
                "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                "00000000",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
            ),
            (
                "0x01",
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
                "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                "bd16bee5",
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
                seed,
                public_key,
                chain_code,
                parent_fingerprint,
                xpub
            ) = KEYPAIR_TREE_HARDENED[0];
            test_from_private(
                public_key,
                chain_code,
                parent_fingerprint,
                xpub,
                seed
            );
        }

        #[test]
        fn test_from_private_normal() {
            let (
                _,
                seed,
                public_key,
                chain_code,
                parent_fingerprint,
                xpub
            ) = KEYPAIR_TREE_NORMAL[0];
            test_from_private(
                public_key,
                chain_code,
                parent_fingerprint,
                xpub,
                seed
            );
        }

        #[test]
        fn test_ckd_pub_normal() {
            let (_, seed, _, _, _, _) = KEYPAIR_TREE_NORMAL[0];
            let seed_bytes = hex::decode(seed).unwrap();
            let parent_xpriv = BitcoinExtendedPrivateKey::new(&seed_bytes);
            let mut parent_xpub = parent_xpriv.to_xpub();
            for (i,
                (
                    _,
                    _,
                    public_key,
                    chain_code,
                    parent_fingerprint,
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
        #[should_panic(expected = "Cannot derive hardened child from extended public key")]
        fn test_ckd_pub_hardened_panic() {
            let (_, seed, _, _, _, _) = KEYPAIR_TREE_HARDENED[0];
            let seed_bytes = hex::decode(seed).unwrap();
            let parent_xpriv = BitcoinExtendedPrivateKey::new(&seed_bytes);
            let parent_xpub = parent_xpriv.to_xpub();
            let _result = parent_xpub.ckd_pub(2_u32.pow(31));
        }

    }
}
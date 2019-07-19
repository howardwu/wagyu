use crate::address::{BitcoinAddress, Format};
use crate::extended_public_key::BitcoinExtendedPublicKey;
use crate::network::BitcoinNetwork;
use crate::private_key::BitcoinPrivateKey;
use crate::public_key::BitcoinPublicKey;
use wagu_model::{
    AddressError,
    ExtendedPublicKey,
    ExtendedPrivateKey,
    ExtendedPrivateKeyError,
    PrivateKey,
    crypto::{checksum, hash160}
};

use base58::{FromBase58, ToBase58};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use hmac::{Hmac, Mac};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Sha512;
use std::{fmt, fmt::Display};
use std::io::Cursor;
use std::str::FromStr;
use std::ops::AddAssign;

type HmacSha512 = Hmac<Sha512>;

/// Represents a Bitcoin extended private key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitcoinExtendedPrivateKey {
    /// The Bitcoin private key
    pub private_key: BitcoinPrivateKey,
    /// The chain code for this extended private key
    pub chain_code: [u8; 32],
    /// The network of this extended private key
    pub network: BitcoinNetwork,
    /// The depth of key derivation, e.g. 0x00 for master nodes, 0x01 for level-1 derived keys, ...
    pub depth: u8,
    /// The first 32 bits of the key identifier (hash160(ECDSA_public_key))
    pub parent_fingerprint: [u8; 4],
    /// This is ser32(i) for i in x_i = x_par/i, with x_i the key being serialized (0x00000000 if master key)
    pub child_number: u32,
}

impl ExtendedPrivateKey for BitcoinExtendedPrivateKey {
    type Address = BitcoinAddress;
    type ExtendedPublicKey = BitcoinExtendedPublicKey;
    type Format = Format;
    type Network = BitcoinNetwork;
    type PrivateKey = BitcoinPrivateKey;
    type PublicKey = BitcoinPublicKey;

    /// Returns a new Bitcoin extended private key.
    fn new(seed: &[u8], network: &BitcoinNetwork) -> Result<Self, ExtendedPrivateKeyError> {
        BitcoinExtendedPrivateKey::new_master(seed, network)
    }

    /// Returns the extended public key of the corresponding extended private key.
    fn to_extended_public_key(&self) -> Self::ExtendedPublicKey {
        BitcoinExtendedPublicKey::from_extended_private_key(&self)
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

impl BitcoinExtendedPrivateKey {
    /// Returns a new Bitcoin extended master private key.
    fn new_master(seed: &[u8], network: &BitcoinNetwork) -> Result<Self, ExtendedPrivateKeyError> {
        let mut mac = HmacSha512::new_varkey(b"Bitcoin seed")?;
        mac.input(seed);
        let result = mac.result().code();
        let (private_key, chain_code) = BitcoinExtendedPrivateKey::derive_private_key_and_chain_code(&result, network)?;
        Ok(Self {
            private_key,
            chain_code,
            network: *network,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0x00000000,
        })
    }

    /// Returns the extended private key of the given derivation path.
    pub fn derivation_path(&self, path: &str) -> Result<Self, ExtendedPrivateKeyError> {
        let mut path_vec: Vec<&str> = path.split("/").collect();

        if path_vec[0] != "m" {
            return Err(ExtendedPrivateKeyError::InvalidDerivationPath("m".into(), path_vec[0].into()))
        }

        if path_vec.len() == 1 {
            return Ok(self.clone())
        }

        let mut xpriv = self.clone();
        for (i, child_str) in path_vec[1..].iter_mut().enumerate() {
            let mut child_num = 0u32;

            // Add 2^31 for hardened paths
            if child_str.contains("'") {
                let child_num_trimmed: u32 = match child_str.trim_end_matches("'").parse() {
                    Ok(num) => num,
                    Err(_) => return Err(ExtendedPrivateKeyError::InvalidDerivationPath("number".into(), path_vec[i+1].into()))
                };
                child_num.add_assign(child_num_trimmed);
                child_num.add_assign(2u32.pow(31));
            } else {
                let child_num_u32: u32 = match child_str.parse() {
                    Ok(num) => num,
                    Err(_) => return Err(ExtendedPrivateKeyError::InvalidDerivationPath("number".into(), path_vec[i+1].into()))
                };
                child_num.add_assign(child_num_u32);
            }
            xpriv = xpriv.ckd_priv(child_num)?;
        }

        Ok(xpriv)
    }

    /// Returns the child extended private key for the given child number.
    pub fn ckd_priv(&self, child_number: u32) -> Result<Self, ExtendedPrivateKeyError> {
        if self.depth == 255 {
            return Err(ExtendedPrivateKeyError::MaximumChildDepthReached(self.depth))
        }

        let mut mac = HmacSha512::new_varkey(&self.chain_code)?;
        let public_key_serialized = &PublicKey::from_secret_key(
            &Secp256k1::new(), &self.private_key.secret_key).serialize()[..];

        // Check whether i ≥ 2^31 (whether the child is a hardened key).
        //
        // If so (hardened child):
        //     let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i))
        //     (Note: The 0x00 pads the private key to make it 33 bytes long.)
        // If not (normal child):
        //     let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
        //
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

        let (mut private_key, chain_code) = BitcoinExtendedPrivateKey::derive_private_key_and_chain_code(&result, &self.network)?;
        private_key.secret_key.add_assign(&Secp256k1::new(), &self.private_key.secret_key)?;

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

        Ok(Self {
            private_key,
            chain_code,
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,
        })
    }

    /// Returns the extended private key and chain code.
    pub fn derive_private_key_and_chain_code(
        result: &[u8],
        network: &BitcoinNetwork
    ) -> Result<(BitcoinPrivateKey, [u8; 32]), ExtendedPrivateKeyError> {
        let private_key = BitcoinPrivateKey::from_secret_key(
            SecretKey::from_slice(&Secp256k1::without_caps(), &result[0..32])?,
            network,
            true,
        );

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&result[32..]);

        return Ok((private_key, chain_code))
    }
}

impl FromStr for BitcoinExtendedPrivateKey {
    type Err = ExtendedPrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58()?;
        if data.len() != 82 {
            return Err(ExtendedPrivateKeyError::InvalidByteLength(data.len()))
        }

        // TODO (howardwu): Move this to network.rs
        let network = if &data[0..4] == [0x04u8, 0x88, 0xAD, 0xE4] {
            BitcoinNetwork::Mainnet
        } else if &data[0..4] == [0x04u8, 0x35, 0x83, 0x94] {
            BitcoinNetwork::Testnet
        } else {
            return Err(ExtendedPrivateKeyError::InvalidNetworkBytes(data[0..4].to_vec()))
        };

        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_number: u32 = Cursor::new(&data[9..13]).read_u32::<BigEndian>()?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let private_key = BitcoinPrivateKey::from_secret_key(
            SecretKey::from_slice(&Secp256k1::new(), &data[46..78])?,
            &network,
            true);

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(ExtendedPrivateKeyError::InvalidChecksum(expected, found))
        }

        Ok(Self { private_key, chain_code, network, depth, parent_fingerprint, child_number })
    }
}

impl Display for BitcoinExtendedPrivateKey {
    /// BIP32 serialization format
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(&match self.network {
            BitcoinNetwork::Mainnet => [0x04, 0x88, 0xAD, 0xE4],
            BitcoinNetwork::Testnet => [0x04, 0x35, 0x83, 0x94],
        }[..]);
        result[4] = self.depth;
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
    use std::string::String;

    fn test_from_str(
        expected_secret_key: &str,
        expected_chain_code: &str,
        expected_depth: u8,
        expected_parent_fingerprint: &str,
        expected_child_number: u32,
        expected_xpriv_serialized: &str,
    ) {
        let xpriv = BitcoinExtendedPrivateKey::from_str(&expected_xpriv_serialized).expect("error generating xpriv object");
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
        let xpriv = BitcoinExtendedPrivateKey::new(&seed_bytes, &BitcoinNetwork::Mainnet).unwrap();
        assert_eq!(expected_secret_key, xpriv.private_key.secret_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(xpriv.chain_code));
        assert_eq!(0, xpriv.depth);
        assert_eq!(expected_parent_fingerprint, hex::encode(xpriv.parent_fingerprint));
        assert_eq!(0, xpriv.child_number);
        assert_eq!(expected_xpriv_serialized, xpriv.to_string());
    }

    fn test_to_extended_public_key(expected_xpub_serialized: &str, xpriv: &BitcoinExtendedPrivateKey) {
        let xpub = xpriv.to_extended_public_key();
        assert_eq!(expected_xpub_serialized, xpub.to_string());
    }

    fn test_ckd_priv(
        expected_secret_key: &str,
        expected_chain_code: &str,
        expected_parent_fingerprint: &str,
        expected_xpriv_serialized: &str,
        expected_xpub_serialized: &str,
        parent_xpriv: &BitcoinExtendedPrivateKey,
        child_number: u32,
    ) -> BitcoinExtendedPrivateKey {
        let child_xpriv = parent_xpriv.ckd_priv(child_number).unwrap();
        assert_eq!(expected_secret_key, child_xpriv.private_key.secret_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(child_xpriv.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(child_xpriv.parent_fingerprint));
        assert_eq!(expected_xpriv_serialized, child_xpriv.to_string());
        assert_eq!(expected_xpub_serialized, child_xpriv.to_extended_public_key().to_string());
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
        master_xpriv: &BitcoinExtendedPrivateKey,
        path: &str,
    ) {
        let derived_xpriv = master_xpriv.derivation_path(path).unwrap();
        assert_eq!(expected_secret_key, derived_xpriv.private_key.secret_key.to_string());
        assert_eq!(expected_chain_code, hex::encode(derived_xpriv.chain_code));
        assert_eq!(expected_parent_fingerprint, hex::encode(derived_xpriv.parent_fingerprint));
        assert_eq!(expected_child_number, derived_xpriv.child_number);
        assert_eq!(expected_xpriv_serialized, derived_xpriv.to_string());
        assert_eq!(expected_xpub_serialized, derived_xpriv.to_extended_public_key().to_string());
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

        const TEST_VECTOR_3: [(&str, &str, &str, &str); 2] = [
            (
                "m",
                "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
                "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
            ),
            (
                "m/0'",
                "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
                "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
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
        fn test_to_extended_public_key_tv1() {
            let (_, _, _, _, _, xpriv_serialized, xpub_serialized) = TEST_VECTOR_1[0];
            let xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            test_to_extended_public_key(xpub_serialized, &xpriv);
        }

        #[test]
        fn test_to_extended_public_key_tv2() {
            let (_, _, _, _, _, xpriv_serialized, xpub_serialized) = TEST_VECTOR_2[0];
            let xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
            test_to_extended_public_key(xpub_serialized, &xpriv);
        }

        #[test]
        fn test_ckd_priv_tv1() {
            let (_, _, _, _, _, xpriv_serialized, _) = TEST_VECTOR_1[0];
            let mut parent_xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
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
            let mut parent_xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
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
            let xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_master).unwrap();
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
            let master_xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
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
            let master_xpriv = BitcoinExtendedPrivateKey::from_str(&xpriv_serialized).unwrap();
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

        #[test]
        fn test_vector_3() {
            // this tests for the retention of leading zeros
            let (path, seed, xpriv_serialized, xpub_serialized) = TEST_VECTOR_3[0];
            let seed_bytes = hex::decode(seed).expect("Error decoding hex seed");
            let master_xpriv = BitcoinExtendedPrivateKey::new(&seed_bytes, &BitcoinNetwork::Mainnet).unwrap();
            assert_eq!(master_xpriv.to_string(), xpriv_serialized);
            assert_eq!(master_xpriv.derivation_path(path).unwrap().to_string(), xpriv_serialized);
            assert_eq!(master_xpriv.to_extended_public_key().to_string(), xpub_serialized);

            let (path, _, xpriv_serialized, xpub_serialized) = TEST_VECTOR_3[1];
            let child_xpriv = master_xpriv.ckd_priv(2147483648).unwrap();
            assert_eq!(child_xpriv.to_string(), xpriv_serialized);
            assert_eq!(master_xpriv.derivation_path(path).unwrap().to_string(), xpriv_serialized);
            assert_eq!(child_xpriv.to_extended_public_key().to_string(), xpub_serialized);
        }
    }

    mod bip44 {
        use super::*;

        #[test]
        fn test_derivation_path() {
            let path = "m/44'/0'/0/1";
            let expected_xpriv_serialized = "xprvA1ErCzsuXhpB8iDTsbmgpkA2P8ggu97hMZbAXTZCdGYeaUrDhyR8fEw47BNEgLExsWCVzFYuGyeDZJLiFJ9kwBzGojQ6NB718tjVJrVBSrG";
            let master_xpriv = BitcoinExtendedPrivateKey::from_str("xprv9s21ZrQH143K4KqQx9Zrf1eN8EaPQVFxM2Ast8mdHn7GKiDWzNEyNdduJhWXToy8MpkGcKjxeFWd8oBSvsz4PCYamxR7TX49pSpp3bmHVAY").unwrap();
            let xpriv = master_xpriv.derivation_path(path).unwrap();
            assert_eq!(expected_xpriv_serialized, xpriv.to_string());
        }
    }

//    mod bip49 {
//        use super::*;
//
//        #[test]
//        fn test_bip49() {
//            let seed = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd";
//            let seed_bytes = hex::decode(seed).expect("Error decoding hex seed");
//            let master_xpriv = BitcoinExtendedPrivateKey::new(&seed_bytes, &Network::Mainnet);
//            let root_path = "m/49'/1'/0'";
//            let expected_xpriv_serialized = "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY";
//            let root_xpriv = master_xpriv.derivation_path(&root_path);
//            assert_eq!(root_xpriv.to_string(), expected_xpriv_serialized);
//
//            let account_path = "m/49'/1'/0'/0/0";
//            let expected_private_key = "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ";
//            let account_xpriv = master_xpriv.derivation_path(&account_path);
//            assert_eq!(account_xpriv.private_key.to_string(), expected_private_key);
//        }
//    }

    mod test_invalid {
        use super::*;

        const INVALID_PATH: &str = "/0";
        const INVALID_PATH_HARDENED: &str = "m/a'";
        const INVALID_PATH_NORMAL: &str = "m/a";
        const INVALID_XPRIV_SECRET_KEY: &str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW";
        const INVALID_XPRIV_NETWORK: &str = "xprv8s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        const INVALID_XPRIV_CHECKSUM: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHj";
        const VALID_XPRIV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        const VALID_XPRIV_FINAL: &str = "xprvJ9DiCzes6yvKjEy8duXR1Qg6Et6CBmrR4yFJvnburXG4X6VnKbNxoTYhvVdpsxkjdXwX3D2NJHFCAnnN1DdAJCVQitnFbFWv3fL3oB2BFo4";

        #[test]
        #[should_panic(expected = "Crate(\"secp256k1\", \"InvalidSecretKey\")")]
        fn from_str_invalid_secret_key() {
            let _result = BitcoinExtendedPrivateKey::from_str(INVALID_XPRIV_SECRET_KEY).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidNetworkBytes([4, 136, 173, 227])")]
        fn from_str_invalid_network() {
            let _result = BitcoinExtendedPrivateKey::from_str(INVALID_XPRIV_NETWORK).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidChecksum(\"6vCfku\", \"6vCfkt\")")]
        fn from_str_invalid_checksum() {
            let _result = BitcoinExtendedPrivateKey::from_str(INVALID_XPRIV_CHECKSUM).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(81)")]
        fn from_str_short() {
            let _result = BitcoinExtendedPrivateKey::from_str(&VALID_XPRIV[1..]).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidByteLength(83)")]
        fn from_str_long() {
            let mut string = String::from(VALID_XPRIV);
            string.push('a');
            let _result = BitcoinExtendedPrivateKey::from_str(&string).unwrap();
        }

        #[test]
        #[should_panic(expected = "MaximumChildDepthReached(255)")]
        fn ckd_priv_max_depth() {
            let mut xpriv = BitcoinExtendedPrivateKey::from_str(VALID_XPRIV).unwrap();
            for _ in 0..255 {
                xpriv = xpriv.ckd_priv(0).unwrap();
            }
            assert_eq!(xpriv.to_string(), VALID_XPRIV_FINAL);
            let _result = xpriv.ckd_priv(0).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidDerivationPath(\"m\", \"\")")]
        fn derivation_path_invalid() {
            let xpriv = BitcoinExtendedPrivateKey::from_str(VALID_XPRIV).unwrap();
            let _result = xpriv.derivation_path(INVALID_PATH).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidDerivationPath(\"number\", \"a\")")]
        fn derivation_path_invalid_digit_normal() {
            let xpriv = BitcoinExtendedPrivateKey::from_str(VALID_XPRIV).unwrap();
            let _result = xpriv.derivation_path(INVALID_PATH_NORMAL).unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidDerivationPath(\"number\", \"a\\'\")")]
        fn derivation_path_invalid_digit_hardened() {
            let xpriv = BitcoinExtendedPrivateKey::from_str(VALID_XPRIV).unwrap();
            let _result = xpriv.derivation_path(INVALID_PATH_HARDENED).unwrap() ;
        }
    }
}
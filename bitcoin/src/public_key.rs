use address::{BitcoinAddress, Format};
use model::{Address, PublicKey, bytes::{FromBytes, ToBytes}};
use network::Network;
use private_key::BitcoinPrivateKey;

use secp256k1;
use std::{fmt, fmt::Display};
use std::io::{Read, Result as IoResult, Write};

/// Represents a Bitcoin public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinPublicKey {
    /// The ECDSA public key
    pub public_key: secp256k1::PublicKey,
    /// If true, the public key is serialized in compressed form
    pub compressed: bool,
}

impl PublicKey for BitcoinPublicKey {
    type Address = BitcoinAddress;
    type Format = Format;
    type Network = Network;
    type PrivateKey = BitcoinPrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key.secret_key);
        Self { public_key, compressed: private_key.compressed }
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: Option<Self::Format>, network: Option<Self::Network>) -> Self::Address {
        BitcoinAddress::from_public_key(self, format, network)
    }
}

//impl FromBytes for BitcoinPublicKey {
//    #[inline]
//    fn read<R: Read>(reader: R) -> IoResult<Self> {
//        let mut f = reader;
//        let mut buffer = Vec::new();
//        f.read_to_end(&mut buffer)?;
//
//        let compressed: bool = match buffer.len() {
//            33 => true,
//            65 => false,
//            len =>  { return Err(String::from_usize(len)); },
//        };
//
//        let secp = secp256k1::Secp256k1::new();
//        let public_key = secp256k1::PublicKey::from_slice(&secp, buffer.as_slice())?;
//        Ok(Self { public_key, compressed })
//    }
//}
//
//impl ToBytes for BitcoinPublicKey {
//    #[inline]
//    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
//        let mut buf = Vec::new();
//        self.write_into(&mut buf);
//        buf
//    }
//}

impl Display for BitcoinPublicKey {
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

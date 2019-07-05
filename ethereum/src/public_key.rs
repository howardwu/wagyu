use address::{EthereumAddress, Format};
use model::{
    //    bytes::{FromBytes, ToBytes},
    Address,
    PublicKey,
};
use network::Network;
use private_key::EthereumPrivateKey;

use secp256k1;
//use std::io::{Read, Result as IoResult, Write};
use std::{fmt, fmt::Display};

/// Represents an Ethereum public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumPublicKey {
    /// The ECDSA public key
    pub public_key: secp256k1::PublicKey,
}

impl PublicKey for EthereumPublicKey {
    type Address = EthereumAddress;
    type Format = (Format, Network);
    type PrivateKey = EthereumPrivateKey;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key.secret_key);
        Self { public_key }
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: Option<Self::Format>) -> Self::Address {
        EthereumAddress::from_public_key(self, format)
    }
}

//impl FromBytes for EthereumPublicKey {
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
//impl ToBytes for EthereumPublicKey {
//    #[inline]
//    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
//        let mut buf = Vec::new();
//        self.write_into(&mut buf);
//        buf
//    }
//}

impl Display for EthereumPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for s in &self.public_key.serialize_uncompressed()[..] {
            write!(f, "{:02x}", s)?;
        }
        Ok(())
    }
}

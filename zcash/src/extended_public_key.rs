use crate::address::{ZcashAddress, Format};
use crate::extended_private_key::ZcashExtendedPrivateKey;
use crate::network::ZcashNetwork;
use crate::public_key::{SaplingViewingKey, ViewingKey, ZcashPublicKey};
use wagu_model::{
    Address,
    AddressError,
    ExtendedPublicKey,
    ExtendedPublicKeyError,
};

use bech32::{Bech32, FromBase32, ToBase32};
use std::cmp::Ordering;
use std::{fmt, fmt::Display};
use std::marker::PhantomData;
use std::str::FromStr;
use zcash_primitives::zip32::ExtendedFullViewingKey;

/// Represents a Zcash extended public key
#[derive(Debug, Clone)]
pub struct ZcashExtendedPublicKey<N: ZcashNetwork> {
    /// The extended full viewing key
    pub extended_full_viewing_key: ExtendedFullViewingKey,
    /// PhantomData
    _network: PhantomData<N>
}

impl <N: ZcashNetwork> ExtendedPublicKey for ZcashExtendedPublicKey<N> {
    type Address = ZcashAddress<N>;
    type ExtendedPrivateKey = ZcashExtendedPrivateKey<N>;
    type Format = Format;
    type PublicKey = ZcashPublicKey<N>;

    /// Returns the extended public key of the corresponding extended private key.
    fn from_extended_private_key(extended_private_key: &Self::ExtendedPrivateKey) -> Self {
        Self {
            extended_full_viewing_key:
                ExtendedFullViewingKey::from(&extended_private_key.extended_spending_key),
            _network: PhantomData
        }
    }

    /// Returns the public key of the corresponding extended public key.
    fn to_public_key(&self) -> Self::PublicKey {
        ZcashPublicKey(
            ViewingKey::Sapling(SaplingViewingKey(self.extended_full_viewing_key.fvk.clone())),
            PhantomData)
    }

    /// Returns the address of the corresponding extended public key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(&self.to_public_key(), format)
    }
}

impl <N: ZcashNetwork> FromStr for ZcashExtendedPublicKey<N> {
    type Err = ExtendedPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bech32 = Bech32::from_str(s)?;
        // Check that the network prefix is correct
        let _ = N::from_extended_public_key_prefix(bech32.hrp())?;

        let data: Vec<u8> = FromBase32::from_base32(bech32.data())?;
        match ExtendedFullViewingKey::read(data.as_slice()) {
            Ok(extended_full_viewing_key) => Ok(Self {
                extended_full_viewing_key, _network: PhantomData
            }),
            Err(error) => Err(ExtendedPublicKeyError::Message(error.to_string()))
        }
    }
}

impl <N: ZcashNetwork> Display for ZcashExtendedPublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data = vec![];
        match self.extended_full_viewing_key.write(&mut data) {
            Ok(_) => (), Err(_) => return Err(fmt::Error)
        };
        match Bech32::new(N::to_extended_public_key_prefix(), data.to_base32()) {
            Ok(key) => write!(f, "{}", key),
            _ => Err(fmt::Error)
        }
    }
}

impl <N: ZcashNetwork> PartialEq for ZcashExtendedPublicKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl <N: ZcashNetwork> Eq for ZcashExtendedPublicKey<N> {}

impl <N: ZcashNetwork> PartialOrd for ZcashExtendedPublicKey<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.to_string().cmp(&other.to_string()))
    }
}

impl <N: ZcashNetwork> Ord for ZcashExtendedPublicKey<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

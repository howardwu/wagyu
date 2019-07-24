use crate::address::{ZcashAddress, Format};
use crate::extended_public_key::ZcashExtendedPublicKey;
use crate::network::ZcashNetwork;
use crate::private_key::{SaplingSpendingKey, SpendingKey, ZcashPrivateKey};
use crate::public_key::ZcashPublicKey;
use wagu_model::{
    Address,
    AddressError,
    ExtendedPrivateKey,
    ExtendedPrivateKeyError,
    ExtendedPublicKey,
    PublicKey
};

use bech32::{Bech32, FromBase32, ToBase32};
use std::cmp::Ordering;
use std::{fmt, fmt::Display};
use std::marker::PhantomData;
use std::str::FromStr;
use zcash_primitives::zip32::ExtendedSpendingKey;

/// Represents a Zcash extended private key
#[derive(Debug, Clone)]
pub struct ZcashExtendedPrivateKey<N: ZcashNetwork> {
    /// The extended spending key
    pub extended_spending_key: ExtendedSpendingKey,
    /// PhantomData
    _network: PhantomData<N>
}

impl <N: ZcashNetwork> ExtendedPrivateKey for ZcashExtendedPrivateKey<N> {
    type Address = ZcashAddress<N>;
    type ExtendedPublicKey = ZcashExtendedPublicKey<N>;
    type Format = Format;
    type PrivateKey = ZcashPrivateKey<N>;
    type PublicKey = ZcashPublicKey<N>;

    /// Returns a new extended private key.
    fn new(seed: &[u8], _: &Self::Format) -> Result<Self, ExtendedPrivateKeyError> {
        Ok(Self { extended_spending_key: ExtendedSpendingKey::master(seed), _network: PhantomData })
    }

    /// Returns the extended public key of the corresponding extended private key.
    fn to_extended_public_key(&self) -> Self::ExtendedPublicKey {
        Self::ExtendedPublicKey::from_extended_private_key(self)
    }

    /// Returns the private key of the corresponding extended private key.
    fn to_private_key(&self) -> Self::PrivateKey {
        ZcashPrivateKey(SpendingKey::<N>::Sapling(SaplingSpendingKey {
            spending_key: None,
            expanded_spending_key: self.extended_spending_key.expsk.clone()
        }), PhantomData)
    }

    /// Returns the public key of the corresponding extended private key.
    fn to_public_key(&self) -> Self::PublicKey {
        Self::PublicKey::from_private_key(&self.to_private_key())
    }

    /// Returns the address of the corresponding extended private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_private_key(&self.to_private_key(), format)
    }
}

impl <N: ZcashNetwork> FromStr for ZcashExtendedPrivateKey<N> {
    type Err = ExtendedPrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bech32 = Bech32::from_str(s)?;
        // Check that the network prefix is correct
        let _ = N::from_extended_private_key_prefix(bech32.hrp())?;

        let data: Vec<u8> = FromBase32::from_base32(bech32.data())?;
        match ExtendedSpendingKey::read(data.as_slice()) {
            Ok(extended_spending_key) => Ok(Self {
                extended_spending_key, _network: PhantomData
            }),
            Err(error) => Err(ExtendedPrivateKeyError::Message(error.to_string()))
        }
    }
}

impl <N: ZcashNetwork> Display for ZcashExtendedPrivateKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data = vec![];
        match self.extended_spending_key.write(&mut data) {
            Ok(_) => (), Err(_) => return Err(fmt::Error)
        };
        match Bech32::new(N::to_extended_private_key_prefix(), data.to_base32()) {
            Ok(key) => write!(f, "{}", key),
            _ => Err(fmt::Error)
        }
    }
}

impl <N: ZcashNetwork> PartialEq for ZcashExtendedPrivateKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl <N: ZcashNetwork> Eq for ZcashExtendedPrivateKey<N> {}

impl <N: ZcashNetwork> PartialOrd for ZcashExtendedPrivateKey<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.to_string().cmp(&other.to_string()))
    }
}

impl <N: ZcashNetwork> Ord for ZcashExtendedPrivateKey<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

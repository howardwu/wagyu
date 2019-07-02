//! # Zcash
//!
//! A library for generating Zcash Wallets.

#![forbid(unsafe_code)]

extern crate base58;
extern crate rand;
extern crate ripemd160;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;
extern crate sha2;

pub mod address;

#[cfg(feature = "serde")]
pub mod builder;

pub mod network;
pub use self::network::*;

pub mod privatekey;
pub use self::privatekey::*;

pub mod utils;
pub use self::utils::*;

#[cfg(feature = "serde")]
pub mod wallet;
#[cfg(feature = "serde")]
pub use self::wallet::*;
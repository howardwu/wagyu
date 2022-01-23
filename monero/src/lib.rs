//! # Monero
//!
//! A library for generating Monero wallets.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_extern_crates, dead_code)]

#[macro_use]
extern crate failure;

pub mod address;
pub use self::address::*;

pub mod amount;
pub use self::amount::*;

pub mod mnemonic;
pub use self::mnemonic::*;

pub mod format;
pub use self::format::*;

pub mod network;
pub use self::network::*;

pub mod one_time_key;
pub use self::one_time_key::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

#[cfg(transaction)]
pub mod transaction;
#[cfg(transaction)]
pub use self::transaction::*;

pub mod wordlist;
pub use self::wordlist::*;

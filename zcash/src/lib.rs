//! # Zcash
//!
//! A library for generating Zcash wallets.
#![warn(unused_extern_crates)]
#![forbid(unsafe_code)]

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[macro_use]
extern crate lazy_static;

pub mod address;
pub use self::address::*;

pub mod derivation_path;
pub use self::derivation_path::*;

pub mod extended_private_key;
pub use self::extended_private_key::*;

pub mod extended_public_key;
pub use self::extended_public_key::*;

pub mod format;
pub use self::format::*;

#[cfg_attr(tarpaulin, skip)]
pub mod librustzcash;

pub mod network;
pub use self::network::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

pub mod transaction;
pub use self::transaction::*;

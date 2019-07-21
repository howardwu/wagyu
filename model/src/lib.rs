//! # Model
//!
//! A model for cryptocurrency wallets.

#![forbid(unsafe_code)]

#[macro_use]
extern crate failure;

pub mod address;
pub use self::address::*;

pub mod bip39;

pub mod extended_private_key;
pub use self::extended_private_key::*;

pub mod extended_public_key;
pub use self::extended_public_key::*;

pub mod mnemonic;
pub use self::mnemonic::*;

pub mod network;
pub use self::network::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

pub mod utilities;
pub use self::utilities::*;

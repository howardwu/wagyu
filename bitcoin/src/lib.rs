//! # Bitcoin
//!
//! A library for generating Bitcoin wallets.
#![warn(unused_extern_crates)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate failure;

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

pub mod mnemonic;
pub use self::mnemonic::*;

pub mod network;
pub use self::network::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

mod witness_program;

pub mod wordlist;
pub use self::wordlist::*;

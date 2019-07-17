//! # Bitcoin
//!
//! A library for generating Bitcoin wallets.

#![forbid(unsafe_code)]

pub mod address;
pub use self::address::*;

pub mod network;
pub use self::network::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

pub mod witness_program;
pub use self::witness_program::*;

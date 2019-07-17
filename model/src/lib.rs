//! # Model
//!
//! A model for cryptocurrency wallets.

#![forbid(unsafe_code)]

extern crate byteorder;
#[macro_use] extern crate failure;
extern crate ripemd160;
extern crate sha2;

pub mod address;
pub use self::address::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

pub mod utilities;
pub use self::utilities::*;

//! # Model
//!
//! A model for cryptocurrency wallets.

#![forbid(unsafe_code)]

extern crate byteorder;
extern crate rand;

pub mod address;

//pub mod network;
//pub use self::network::*;

pub mod private_key;
pub use self::private_key::*;

pub mod public_key;
pub use self::public_key::*;

pub mod utilities;
pub use self::utilities::*;

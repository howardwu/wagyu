//! # Ethereum
//!
//! A library for generating Ethereum wallets.

#![forbid(unsafe_code)]

extern crate hex;
extern crate rand;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;
extern crate tiny_keccak;

pub mod address;

pub mod builder;

pub mod keypair;
pub use self::keypair::*;

pub mod utils;
pub use self::utils::*;

pub mod wallet;
pub use self::wallet::*;
